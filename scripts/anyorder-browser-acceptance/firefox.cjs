'use strict';
// Reuse the pinned native BiDi driver without editing historical evidence.
const {Firefox: BaseFirefox,sleep}=require('../../browser-assets-wave8/firefox-bidi.cjs');
class Firefox extends BaseFirefox {
  async keys(values) {
    return this.send('input.performActions',{context:this.context,actions:[{type:'key',id:'keyboard',actions:values.flatMap(value=>[{type:'keyDown',value},{type:'keyUp',value}])}]});
  }
  async fill(selector,value) {
    const state=await this.evaluate(`(()=>{const e=document.querySelector(${JSON.stringify(selector)});return {tag:e.tagName,index:e.tagName==='SELECT'?Array.from(e.options).findIndex(o=>o.value===${JSON.stringify(value)}):-1};})()`);
    if(state.tag==='SELECT') {
      if(state.index<0)throw Error('Missing native select option '+selector);
      // Native closed-select keyboard interaction avoids GTK popup routing.
      // Walk focus with Tab; do not set value or dispatch synthetic events.
      for(let i=0;i<60&&!await this.evaluate(`document.activeElement===document.querySelector(${JSON.stringify(selector)})`);i++)await this.keys(['\uE004']);
      if(!await this.evaluate(`document.activeElement===document.querySelector(${JSON.stringify(selector)})`))throw Error('Native Tab did not reach '+selector);
      await this.keys(['\uE011']);
      for(let i=0;i<state.index;i++)await this.keys(['\uE015']);
    } else {
      await this.click(selector);
      await this.send('input.performActions',{context:this.context,actions:[{type:'key',id:'keyboard',actions:[{type:'keyDown',value:'\uE009'},{type:'keyDown',value:'a'},{type:'keyUp',value:'a'},{type:'keyUp',value:'\uE009'}]}]});
      await this.keys([...String(value)]);
    }
    await this.wait(`document.querySelector(${JSON.stringify(selector)}).value===${JSON.stringify(String(value))}`);
    this.nativeFills??=[];this.nativeFills.push({selector,tag:state.tag,method:state.tag==='SELECT'?'native-tab-home-arrows':'native-pointer-control-a-keys'});
  }
}
module.exports={Firefox,sleep};
