//! MS-TSGU 3.3.5.3.3: NTLM at the RD Gateway layer, no HTTP credential fallback.
use super::*;
use sspi::{
    AuthIdentity, BufferType, ClientRequestFlags, CredentialUse, DataRepresentation, Ntlm,
    SecurityBuffer, SecurityStatus, Sspi, SspiImpl, Username,
};
impl GwConn {
    pub(super) async fn ntlm_auth(&mut self) -> Result<(), Error> {
        let identity = AuthIdentity {
            username: Username::parse(&self.target.gw_user)
                .map_err(|e| custom_err!("Gateway username", e))?,
            password: self.target.gw_pass.clone().into(),
        };
        let mut ntlm = Ntlm::new();
        let mut credentials = ntlm
            .acquire_credentials_handle()
            .with_credential_use(CredentialUse::Outbound)
            .with_auth_data(&identity)
            .execute(&mut ntlm)
            .map_err(|e| custom_err!("Gateway NTLM credentials", e))?;
        let target_name = format!(
            "HTTP/{}",
            self.target
                .gw_endpoint
                .split(':')
                .next()
                .unwrap_or_default()
        );
        let mut incoming = vec![];
        let mut complete = false;
        // NTLM has exactly negotiate, challenge, authenticate, final confirmation.
        for step in 0..3 {
            if step > 0 {
                let (header, bytes) = self.read_packet().await?;
                if header.ty != PktTy::ExtendedAuth {
                    return Err(Error::new(
                        "Expected gateway NTLM response",
                        GwErrorKind::Decode,
                    ));
                }
                let mut cursor = ReadCursor::new(&bytes);
                let packet = proto::ExtendedAuthPkt::decode(&mut cursor)
                    .map_err(|e| custom_err!("Gateway NTLM packet", e))?;
                if packet.error_code != 0 {
                    return Err(Error::new(
                        "Gateway NTLM rejected credentials; no retry",
                        GwErrorKind::Connect,
                    ));
                }
                if complete {
                    if !packet.blob.is_empty() {
                        return Err(Error::new(
                            "Unexpected final NTLM token",
                            GwErrorKind::Decode,
                        ));
                    }
                    return Ok(());
                }
                if packet.blob.is_empty() {
                    return Err(Error::new("Empty NTLM challenge", GwErrorKind::Decode));
                }
                incoming = packet.blob;
            }
            let (is_complete, token) = next_token(
                &mut ntlm,
                &mut credentials.credentials_handle,
                &target_name,
                &incoming,
            )?;
            complete = is_complete;
            self.send_packet(&proto::ExtendedAuthPkt {
                error_code: 0,
                blob: token,
            })
            .await?;
        }
        Err(Error::new("Gateway NTLM round limit", GwErrorKind::Connect))
    }
}

fn next_token(
    ntlm: &mut Ntlm,
    credentials: &mut Option<sspi::AuthIdentityBuffers>,
    target: &str,
    incoming: &[u8],
) -> Result<(bool, Vec<u8>), Error> {
    let mut input = vec![SecurityBuffer::new(incoming.to_vec(), BufferType::Token)];
    let mut output = vec![SecurityBuffer::new(Vec::new(), BufferType::Token)];
    let mut builder = ntlm
        .initialize_security_context()
        .with_credentials_handle(credentials)
        .with_context_requirements(ClientRequestFlags::ALLOCATE_MEMORY)
        .with_target_data_representation(DataRepresentation::Native)
        .with_target_name(target)
        .with_input(&mut input)
        .with_output(&mut output);
    let result = ntlm
        .initialize_security_context_impl(&mut builder)
        .map_err(|e| custom_err!("Gateway NTLM context", e))?
        .resolve_to_result()
        .map_err(|e| custom_err!("Gateway NTLM token", e))?;
    let complete = result.status == SecurityStatus::Ok;
    if !complete && result.status != SecurityStatus::ContinueNeeded {
        return Err(Error::new(
            "Unexpected NTLM security status",
            GwErrorKind::Connect,
        ));
    }
    Ok((complete, std::mem::take(&mut output[0].buffer)))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ntlm_exchange_with_local_fake_server() {
        let identity = AuthIdentity {
            username: Username::parse("TEST\\relayne").unwrap(),
            password: "local-test-only".to_owned().into(),
        };
        let mut client = Ntlm::new();
        let mut server = Ntlm::new();
        let mut client_cred = client
            .acquire_credentials_handle()
            .with_credential_use(CredentialUse::Outbound)
            .with_auth_data(&identity)
            .execute(&mut client)
            .unwrap()
            .credentials_handle;
        let mut server_cred = server
            .acquire_credentials_handle()
            .with_credential_use(CredentialUse::Inbound)
            .with_auth_data(&identity)
            .execute(&mut server)
            .unwrap()
            .credentials_handle;
        let (done, negotiate) =
            next_token(&mut client, &mut client_cred, "HTTP/localhost", &[]).unwrap();
        assert!(!done);
        assert_eq!(&negotiate[..8], b"NTLMSSP\0");
        let mut input = vec![SecurityBuffer::new(negotiate, BufferType::Token)];
        let mut output = vec![SecurityBuffer::new(Vec::new(), BufferType::Token)];
        let builder = server
            .accept_security_context()
            .with_credentials_handle(&mut server_cred)
            .with_context_requirements(sspi::ServerRequestFlags::ALLOCATE_MEMORY)
            .with_target_data_representation(DataRepresentation::Native)
            .with_input(&mut input)
            .with_output(&mut output);
        let result = server
            .accept_security_context_impl(builder)
            .unwrap()
            .resolve_to_result()
            .unwrap();
        assert_eq!(result.status, SecurityStatus::ContinueNeeded);
        let (done, authenticate) = next_token(
            &mut client,
            &mut client_cred,
            "HTTP/localhost",
            &output[0].buffer,
        )
        .unwrap();
        assert!(done);
        input[0].buffer = authenticate;
        output[0].buffer.clear();
        let builder = server
            .accept_security_context()
            .with_credentials_handle(&mut server_cred)
            .with_context_requirements(sspi::ServerRequestFlags::ALLOCATE_MEMORY)
            .with_target_data_representation(DataRepresentation::Native)
            .with_input(&mut input)
            .with_output(&mut output);
        let result = server
            .accept_security_context_impl(builder)
            .unwrap()
            .resolve_to_result()
            .unwrap();
        if result.status == SecurityStatus::CompleteNeeded {
            server.complete_auth_token(&mut output).unwrap();
        }
        assert!(matches!(
            result.status,
            SecurityStatus::Ok | SecurityStatus::CompleteNeeded
        ));
    }
}
