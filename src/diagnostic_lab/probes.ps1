$value='Unknown'
try {
    switch([string]$p.probe){
        'Service' {
            $service=Get-Service -Name ([string]$p.service) -ErrorAction Stop
            $service.Refresh()
            if([string]$service.Status -eq 'Running'){$value='Pass'}
            elseif([string]$service.Status -eq 'Stopped'){$value='Fail'}
        }
        'Dns' {
            try {
                $lookup=[Net.Dns]::GetHostAddressesAsync([string]$p.host)
                if($lookup.Wait(5000) -and $lookup.Result.Length -gt 0){$value='Pass'}
            } catch {
                $problem=$_.Exception
                while($problem.InnerException){$problem=$problem.InnerException}
                if($problem -is [Net.Sockets.SocketException] -and $problem.SocketErrorCode -in @([Net.Sockets.SocketError]::HostNotFound,[Net.Sockets.SocketError]::NoData)){$value='Fail'}
            }
        }
        'Tls' {
            $client=[Net.Sockets.TcpClient]::new();$stream=$null
            try {
                $connect=$client.ConnectAsync([string]$p.host,[int]$p.port)
                if($connect.Wait(5000) -and $client.Connected){
                    $stream=[Net.Security.SslStream]::new($client.GetStream(),$false)
                    try {
                        $auth=$stream.AuthenticateAsClientAsync([string]$p.host)
                        if($auth.Wait(5000) -and $stream.IsAuthenticated){$value='Pass'}
                    } catch {
                        $problem=$_.Exception
                        while($problem){
                            if($problem -is [Security.Authentication.AuthenticationException]){$value='Fail';break}
                            $problem=$problem.InnerException
                        }
                    }
                }
            } finally {if($stream){$stream.Dispose()};$client.Dispose()}
        }
        'Dependency' {
            $uri=[uri]$p.dependency
            if($uri.Scheme -notin @('http','https') -or $uri.UserInfo -or $uri.Query -or $uri.Fragment){throw 'Invalid URL'}
            $request=[Net.HttpWebRequest]::Create($uri)
            $request.Method='GET';$request.AllowAutoRedirect=$false;$request.Proxy=$null;$request.Credentials=$null;$request.UseDefaultCredentials=$false
            $request.Timeout=5000;$request.ReadWriteTimeout=5000;$request.MaximumResponseHeadersLength=16
            $response=$null
            try {
                try{$response=$request.GetResponse()}catch [Net.WebException]{if($_.Exception.Response){$response=$_.Exception.Response}}
                if($response){
                    $status=[int]$response.StatusCode
                    if($status -ge 200 -and $status -le 299){$value='Pass'}
                    elseif($status -ge 500 -and $status -le 599){$value='Fail'}
                }
            } finally {if($response){$response.Dispose()}}
        }
    }
} catch {
    # Missing permissions, unavailable probes and transient states remain unknown.
}
[pscustomobject]@{request=[string]$p.request;binding=[string]$p.binding;probe=[string]$p.probe;value=$value}
