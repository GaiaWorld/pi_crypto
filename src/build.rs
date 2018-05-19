use pi_vm::bonmgr::{BonMgr, StructMeta, FnMeta, jstype_ptr,ptr_jstype, CallResult};
use pi_vm::adapter::{JSType, JS};
use std::sync::Arc;
use pi_vm::pi_vm_impl::{ block_reply};
use pi_vm::task::TaskType;
 use ed25519;
 use hash;



fn call_266558349(js: Arc<JS>, mgr: &BonMgr, v:Vec<JSType>) -> Option<CallResult>{
	let param_error = "param error in ed25519";

	let jst0 = &v[0];
	if !jst0.is_uint8_array() && !jst0.is_array_buffer(){return Some(CallResult::Err(String::from(param_error))); }
    let jst0 = jst0.to_bytes();



	let jst1 = &v[1];
	if !jst1.is_uint8_array() && !jst1.is_array_buffer(){return Some(CallResult::Err(String::from(param_error))); }
    let jst1 = jst1.to_bytes();



	let result = ed25519::exchange(jst0,jst1);
	let ptr = Box::into_raw(Box::new(result)) as usize;let result = ptr_jstype(mgr, js.clone(), ptr,526967798);

    Some(CallResult::Ok)
}


fn call_2282179587(js: Arc<JS>, mgr: &BonMgr, v:Vec<JSType>) -> Option<CallResult>{
	let param_error = "param error in ed25519";

	let jst0 = &v[0];
	if !jst0.is_uint8_array() && !jst0.is_array_buffer(){return Some(CallResult::Err(String::from(param_error))); }
    let jst0 = jst0.to_bytes();



	let result = ed25519::keypair(jst0);
	let array = js.new_array();
    let result_elem = result.0;
	let ptr = Box::into_raw(Box::new(result_elem)) as usize;let result_elem = ptr_jstype(mgr, js.clone(), ptr,2521161042);
js.set_index(&array, 0, &result_elem);
    let result_elem = result.1;
	let ptr = Box::into_raw(Box::new(result_elem)) as usize;let result_elem = ptr_jstype(mgr, js.clone(), ptr,526967798);
js.set_index(&array, 1, &result_elem);
    Some(CallResult::Ok)
}


fn call_1005885597(js: Arc<JS>, mgr: &BonMgr, v:Vec<JSType>) -> Option<CallResult>{
	let param_error = "param error in ed25519";

	let jst0 = &v[0];
	if !jst0.is_uint8_array() && !jst0.is_array_buffer(){return Some(CallResult::Err(String::from(param_error))); }
    let jst0 = jst0.to_bytes();



	let jst1 = &v[1];
	if !jst1.is_uint8_array() && !jst1.is_array_buffer(){return Some(CallResult::Err(String::from(param_error))); }
    let jst1 = jst1.to_bytes();



	let result = ed25519::sign(jst0,jst1);
	let ptr = Box::into_raw(Box::new(result)) as usize;let result = ptr_jstype(mgr, js.clone(), ptr,2521161042);

    Some(CallResult::Ok)
}


fn call_1115867356(js: Arc<JS>, v:Vec<JSType>) -> Option<CallResult>{
	let param_error = "param error in ed25519";

	let jst0 = &v[0];
	if !jst0.is_uint8_array() && !jst0.is_array_buffer(){return Some(CallResult::Err(String::from(param_error))); }
    let jst0 = jst0.to_bytes();



	let jst1 = &v[1];
	if !jst1.is_uint8_array() && !jst1.is_array_buffer(){return Some(CallResult::Err(String::from(param_error))); }
    let jst1 = jst1.to_bytes();



	let jst2 = &v[2];
	if !jst2.is_uint8_array() && !jst2.is_array_buffer(){return Some(CallResult::Err(String::from(param_error))); }
    let jst2 = jst2.to_bytes();



	let result = ed25519::verify(jst0,jst1,jst2);let result = js.new_boolean(result);

    Some(CallResult::Ok)
}


fn call_1476345609(js: Arc<JS>, mgr: &BonMgr, v:Vec<JSType>) -> Option<CallResult>{
	let param_error = "param error in hash";

	let jst0 = &v[0];
	if !jst0.is_uint8_array() && !jst0.is_array_buffer(){return Some(CallResult::Err(String::from(param_error))); }
    let jst0 = jst0.to_bytes();



	let result = hash::ripemd160(jst0);
	let ptr = Box::into_raw(Box::new(result)) as usize;let result = ptr_jstype(mgr, js.clone(), ptr,3995272273);

    Some(CallResult::Ok)
}


fn call_2717525457(js: Arc<JS>, mgr: &BonMgr, v:Vec<JSType>) -> Option<CallResult>{
	let param_error = "param error in hash";

	let jst0 = &v[0];
	if !jst0.is_uint8_array() && !jst0.is_array_buffer(){return Some(CallResult::Err(String::from(param_error))); }
    let jst0 = jst0.to_bytes();



	let result = hash::sha256(jst0);
	let ptr = Box::into_raw(Box::new(result)) as usize;let result = ptr_jstype(mgr, js.clone(), ptr,526967798);

    Some(CallResult::Ok)
}


fn call_842379557(js: Arc<JS>, mgr: &BonMgr, v:Vec<JSType>) -> Option<CallResult>{
	let param_error = "param error in hash";

	let jst0 = &v[0];
	if !jst0.is_uint8_array() && !jst0.is_array_buffer(){return Some(CallResult::Err(String::from(param_error))); }
    let jst0 = jst0.to_bytes();



	let result = hash::dhash160(jst0);
	let ptr = Box::into_raw(Box::new(result)) as usize;let result = ptr_jstype(mgr, js.clone(), ptr,3995272273);

    Some(CallResult::Ok)
}


fn call_1125159944(js: Arc<JS>, mgr: &BonMgr, v:Vec<JSType>) -> Option<CallResult>{
	let param_error = "param error in hash";

	let jst0 = &v[0];
	if !jst0.is_uint8_array() && !jst0.is_array_buffer(){return Some(CallResult::Err(String::from(param_error))); }
    let jst0 = jst0.to_bytes();



	let result = hash::dhash256(jst0);
	let ptr = Box::into_raw(Box::new(result)) as usize;let result = ptr_jstype(mgr, js.clone(), ptr,526967798);

    Some(CallResult::Ok)
}


fn call_796485226(js: Arc<JS>, v:Vec<JSType>) -> Option<CallResult>{
	let param_error = "param error in hash";

	let jst0 = &v[0];
	if !jst0.is_number(){ return Some(CallResult::Err(String::from(param_error)));}
	let jst0 = jst0.get_u64();


	let jst1 = &v[1];
	if !jst1.is_number(){ return Some(CallResult::Err(String::from(param_error)));}
	let jst1 = jst1.get_u64();


	let jst2 = &v[2];
	if !jst2.is_uint8_array() && !jst2.is_array_buffer(){return Some(CallResult::Err(String::from(param_error))); }
    let jst2 = jst2.to_bytes();



	let result = hash::siphash24(jst0,jst1,jst2);let result = js.new_u64(result);

    Some(CallResult::Ok)
}


fn call_235181891(js: Arc<JS>, mgr: &BonMgr, v:Vec<JSType>) -> Option<CallResult>{
	let param_error = "param error in hash";

	let jst0 = &v[0];
	if !jst0.is_uint8_array() && !jst0.is_array_buffer(){return Some(CallResult::Err(String::from(param_error))); }
    let jst0 = jst0.to_bytes();



	let result = hash::checksum(jst0);
	let ptr = Box::into_raw(Box::new(result)) as usize;let result = ptr_jstype(mgr, js.clone(), ptr,3974239134);

    Some(CallResult::Ok)
}
pub fn register(mgr: &mut BonMgr){
    mgr.regist_struct_meta(StructMeta{name:String::from("pi_math::hash::H256")}, 526967798);
    mgr.regist_struct_meta(StructMeta{name:String::from("pi_math::hash::H512")}, 2521161042);
    mgr.regist_struct_meta(StructMeta{name:String::from("pi_math::hash::H160")}, 3995272273);
    mgr.regist_struct_meta(StructMeta{name:String::from("pi_math::hash::H32")}, 3974239134);
    mgr.regist_fun_meta(FnMeta::CallArgNobj(call_266558349), 266558349);
    mgr.regist_fun_meta(FnMeta::CallArgNobj(call_2282179587), 2282179587);
    mgr.regist_fun_meta(FnMeta::CallArgNobj(call_1005885597), 1005885597);
    mgr.regist_fun_meta(FnMeta::CallArg(call_1115867356), 1115867356);
    mgr.regist_fun_meta(FnMeta::CallArgNobj(call_1476345609), 1476345609);
    mgr.regist_fun_meta(FnMeta::CallArgNobj(call_2717525457), 2717525457);
    mgr.regist_fun_meta(FnMeta::CallArgNobj(call_842379557), 842379557);
    mgr.regist_fun_meta(FnMeta::CallArgNobj(call_1125159944), 1125159944);
    mgr.regist_fun_meta(FnMeta::CallArg(call_796485226), 796485226);
    mgr.regist_fun_meta(FnMeta::CallArgNobj(call_235181891), 235181891);
}