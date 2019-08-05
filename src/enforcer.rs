// 核心enforcer类，构造函数和校验方法
use crate::adapter::Adapter;
use crate::effector::{DefaultEffector, Effector};
use crate::model::Model;
use crate::model::{load_function_map, FunctionMap};
use crate::rbac::{DefaultRoleManager, RoleManager};

use rhai::Engine;
use rhai::FnRegister;

pub fn generate_g_function(
    rm: impl RoleManager + 'static,
) -> Box<dyn Fn(Option<Vec<String>>) -> bool> {
    let cb = move |args: Option<Vec<String>>| -> bool {
        let args = args.unwrap();
        let name1 = args[0].clone();
        let name2 = args[1].clone();

        if args.len() == 2 {
            return rm.has_link(name1, name2, None);
        } else {
            let domain = args[2].clone();
            return rm.has_link(name1, name2, Some(vec![domain]));
        }
    };
    return Box::new(cb);
}

// TODO: should implement a default role manager later
pub struct Enforcer {
    pub model: Model,
    pub adapter: Box<Adapter>,
    pub fm: FunctionMap,
    pub eft: Box<Effector>,
    pub rm: Box<RoleManager>,
}

impl Enforcer {
    pub fn new(m: Model, a: Box<Adapter>) -> Self {
        let fm = load_function_map();
        let eft = Box::new(DefaultEffector::default());
        let rm = Box::new(DefaultRoleManager::new(10));
        // TODO: 要通过 build links把rm传给每个assertion map
        let e = Enforcer {
            model: m,
            adapter: a,
            fm,
            eft,
            rm,
        };

        return e;
    }

    pub fn enforce(&self, rvals: Option<Vec<String>>) -> bool {
        let mut functions = Engine::new();
        for (key, func) in self.fm.iter() {
            functions.register_fn(key.as_str(), func.clone());
        }
        // TODO: 要注入一个默认的roleManager之后，才能生成g函数
        if let Some(g_result) = self.model.model.get("g") {
            for (key, ast) in g_result {
                let ast_fm = generate_g_function(ast.rm.unwrap());
                functions.register_fn(key.as_str(), ast.rm);
            }
        }
        return false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::FileAdapter;

    #[test]
    fn test_enforcer() {
        let mut m = Model::new();
        m.add_def("r", "r", "sub, obj, act");
        m.add_def("p", "p", "sub, obj, act");
        m.add_def("e", "e", "some(where (p.eft == allow))");
        m.add_def(
            "m",
            "m",
            "r.sub == p.sub && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)",
        );

        let adapter = FileAdapter::new("/tmp/keymatch_policy.csv");

        let enforcer = Enforcer::new(m, Box::new(adapter));
    }
}
