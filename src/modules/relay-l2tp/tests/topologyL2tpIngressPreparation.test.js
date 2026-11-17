'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const { TopologyDeploymentRepository } = require('../repositories/topologyDeploymentRepository');
const id = n => n.toString(16).padStart(24,'0');
function fixture() {
 const group = { _id: id(3), mode: 'reverse', strategy: 'priority-failover', paths: [{ pathKey: 'main', linkIds: [id(4)], priority: 1, enabled: true }] };
 const baseline = { nodes: [{ id:id(1), role:'relay' },{ id:id(2), role:'bridge' }], links: [{ id:id(4),source:id(1),target:id(2),mode:'reverse' }], groups: [] };
 const selected = { baselineTopology: structuredClone(baseline), effectiveTopology: structuredClone(baseline), resourceNodeIds:[id(1),id(2)], selectedOwnerPins:[], verifiedBaselineGroups:[],
  installedPath: { oldPathLinkIds:[id(4)],newPathLinkIds:[id(4)] } };
 return { group, selected, scope:{kind:'domain.reconcile',linkId:id(4),linkIds:[id(4)]}, snapshot:{groups:[group]} };
}
async function prepare(f) { return TopologyDeploymentRepository.prototype.readIngressPreparation.call({readSelected:async()=>f.selected},f); }
test('ingress preparation composes exact settled before + bound G/K after without pretending MAIN already migrated',async()=>{
 const f=fixture(),r=await prepare(f); assert.deepEqual(r.baselineTopology.groups,[]); assert.deepEqual(r.effectiveTopology.groups,require('../domain/topologyDraft').projectGroups([f.group])); assert.equal(r.installedPath,undefined); assert.deepEqual(r.baselineTopology.links,r.effectiveTopology.links);
});
for(const [label,change]of[
 ['endpoint change',f=>f.selected.effectiveTopology.links[0].target=id(8)],
 ['mode change',f=>f.selected.effectiveTopology.links[0].mode='forward'],
 ['missing old resource',f=>f.scope.linkIds=[]],
 ['unapplied foreign path',f=>f.group.paths[0].linkIds.push(id(9))],
 ['implicit installed path switch',f=>f.selected.installedPath.newPathLinkIds=[]],
 ['policy mutation',f=>f.selected.verifiedBaselineGroups=[{...f.group,mode:'forward'}]],
])test('ingress preparation refuses '+label,async()=>{const f=fixture();change(f);await assert.rejects(prepare(f),{code:'TOPOLOGY_INGRESS_PREPARATION_CHANGED'});});
