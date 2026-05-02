import { controls,evidence,risks,remediations,frameworks } from '../lib/data';
if(controls.length<50||evidence.length<20||risks.length<15||remediations.length<20||frameworks.length!==5) throw new Error('Seed validation failed');
console.log('seed validation passed');
