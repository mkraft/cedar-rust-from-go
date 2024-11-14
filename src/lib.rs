use cedar_policy::*;
use std::ffi::{CStr};
use std::os::raw::c_char;

#[no_mangle]
pub extern "C" fn is_authorized(principal: *const c_char, action: *const c_char, resource: *const c_char, policy: *const c_char, entities: *const c_char) -> bool {
        let c_str_policy = unsafe { CStr::from_ptr(policy) };
        let input_policy = c_str_policy.to_str().unwrap_or("");
        let policy: PolicySet = input_policy.parse().unwrap();
    
        let c_str_principal = unsafe { CStr::from_ptr(principal) };
        let input_principal = c_str_principal.to_str().unwrap_or("");
        let principal = input_principal.parse().unwrap();

        let c_str_action = unsafe { CStr::from_ptr(action) };
        let input_principal = c_str_action.to_str().unwrap_or("");
        let action = input_principal.parse().unwrap();

        let c_str_resource = unsafe { CStr::from_ptr(resource) };
        let input_resource = c_str_resource.to_str().unwrap_or("");
        let resource = input_resource.parse().unwrap();

        let request = Request::new(principal, action, resource, Context::empty(), None).unwrap();
    
        
        let c_str_entities = unsafe { CStr::from_ptr(entities) };
        let input_entities = c_str_entities.to_str().unwrap_or("");
        let entities: Entities = Entities::from_json_str(input_entities, None).unwrap();
        
        let authorizer = Authorizer::new();
        let answer = authorizer.is_authorized(&request, &policy, &entities);
    
        answer.decision() == Decision::Allow
}