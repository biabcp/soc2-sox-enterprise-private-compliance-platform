import { NextResponse } from 'next/server';
import { controls,evidence,risks,remediations } from '@/lib/data';
export async function GET(_:Request,{params}:{params:{type:string}}){
 const t=params.type;
 if(t==='crosswalk') return new NextResponse('control_id,name,framework\n'+controls.map(c=>`${c.id},${c.name},${c.framework}`).join('\n'),{headers:{'content-type':'text/csv'}});
 if(t==='evidence') return NextResponse.json({framework:'SOC 2',records:evidence});
 if(t==='risks') return new NextResponse('risk_id,title,score,severity\n'+risks.map(r=>`${r.id},${r.title},${r.score},${r.severity}`).join('\n'),{headers:{'content-type':'text/csv'}});
 if(t==='remediation') return new NextResponse('id,title,status,owner\n'+remediations.map(r=>`${r.id},${r.title},${r.status},${r.owner}`).join('\n'),{headers:{'content-type':'text/csv'}});
 return NextResponse.json({reports:[{name:'board-summary',overall:72}]});
}
