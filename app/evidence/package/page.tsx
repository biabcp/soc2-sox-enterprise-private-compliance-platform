import { evidence } from '@/lib/data';
export default function P(){return <div className='space-y-3'><h2 className='text-2xl'>Auditor-ready package summary</h2><div className='card'>Selected framework: SOC 2<br/>Audit period: 2026-Q2<br/>Artifacts: {evidence.length} evidence records, owners, statuses, notes.</div><a href='/api/export/evidence' className='text-blue-600'>Export JSON</a></div>}
