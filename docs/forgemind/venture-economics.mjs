import { writeFileSync } from 'node:fs';
const inputs = [
  {name:'Konservativ',reachableAccounts:30,newAccountsPerMonth:1,seats:3,price:9.99,churn:0.04,grossMargin:0.70,cac:500,build:15000,fixedMonthly:0},
  {name:'Basis',reachableAccounts:100,newAccountsPerMonth:3,seats:5,price:9.99,churn:0.02,grossMargin:0.80,cac:600,build:25000,fixedMonthly:0},
  {name:'Positiv',reachableAccounts:250,newAccountsPerMonth:8,seats:10,price:9.99,churn:0.01,grossMargin:0.85,cac:600,build:25000,fixedMonthly:0}
];
function calculate(s) {
  let accounts=0,revenue=0;
  const months=[];
  for(let month=1;month<=12;month++){
    accounts=accounts*(1-s.churn)+s.newAccountsPerMonth;
    const monthlyRevenue=accounts*s.seats*s.price;
    revenue+=monthlyRevenue;
    months.push({month,accounts,revenue:monthlyRevenue});
  }
  const contributionPerAccount=s.seats*s.price*s.grossMargin;
  return {...s,months,endAccounts:accounts,revenue,grossProfit:revenue*s.grossMargin,
    acquisitionCost:12*s.newAccountsPerMonth*s.cac,
    net12:revenue*s.grossMargin-12*s.newAccountsPerMonth*s.cac-12*s.fixedMonthly-s.build,
    operatingBreakEvenAccounts:Math.ceil(s.fixedMonthly/contributionPerAccount),
    breakEvenWithAcquisition:Math.ceil((s.fixedMonthly+s.newAccountsPerMonth*s.cac)/contributionPerAccount),
    cacPaybackMonths:s.cac/contributionPerAccount};
}
const scenarios=inputs.map(calculate);
const base=inputs[1];
const sensitivity=[
  ['Preis -20%',{price:base.price*.8}],['Preis +20%',{price:base.price*1.2}],
  ['Neukunden halbiert',{newAccountsPerMonth:1.5}],['Neukunden verdoppelt',{newAccountsPerMonth:6}],
  ['CAC +50%',{cac:900}],['Churn 4%',{churn:.04}],['Fixkosten +1000 EUR',{fixedMonthly:1000}]
].map(([change,patch])=>({change,net12:calculate({...base,...patch}).net12}));
const result={boundary:'User-selected starting price EUR 9.99 per seat/month; net VAT treatment assumed. All other inputs are illustrative analyst assumptions, not forecasts. Accounts are paying organizations. No market sizing or demand evidence.',scenarios,sensitivity};
writeFileSync(new URL('./venture-economics.json',import.meta.url),JSON.stringify(result,null,2)+'\n');
console.log(JSON.stringify({scenarios:scenarios.map(({months,...s})=>s),sensitivity},null,2));


