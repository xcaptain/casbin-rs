// 核心enforcer类，构造函数和校验方法
use crate::adapter::FileAdapter;
use crate::effector::{DefaultEffector, EffectKind, Effector};
use crate::model::Model;
use crate::model::{load_function_map, FunctionMap};
use crate::rbac::{DefaultRoleManager, RoleManager};
use std::collections::HashMap;

use rhai::{Engine, FnRegister, Scope};

pub trait MatchFnClone: Fn(Vec<String>) -> bool {
    fn clone_box(&self) -> Box<dyn MatchFnClone>;
}

impl<T> MatchFnClone for T
where
    T: 'static + Fn(Vec<String>) -> bool + Clone,
{
    fn clone_box(&self) -> Box<dyn MatchFnClone> {
        Box::new(self.clone())
    }
}

impl Clone for Box<dyn MatchFnClone> {
    fn clone(&self) -> Self {
        (**self).clone_box()
    }
}

// 至少长度为2
pub fn generate_g_function(rm: DefaultRoleManager) -> Box<dyn MatchFnClone> {
    let cb = move |args: Vec<String>| -> bool {
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

#[derive(Default)]
pub struct EnforceParameters {
    pub r_tokens: HashMap<String, usize>,
    pub r_vals: Vec<String>,

    pub p_tokens: HashMap<String, usize>,
    pub p_vals: Vec<String>,
}

// TODO: should implement a default role manager later
pub struct Enforcer {
    pub model: Model,
    pub adapter: FileAdapter,
    pub fm: FunctionMap,
    pub eft: DefaultEffector,
    pub rm: DefaultRoleManager,
}

impl Enforcer {
    pub fn new(m: Model, a: FileAdapter) -> Self {
        let fm = load_function_map();
        let eft = DefaultEffector::default();
        let rm = DefaultRoleManager::new(10);
        // TODO: 要通过 build links把rm传给每个assertion map
        let e = Self {
            model: m,
            adapter: a,
            fm,
            eft,
            rm,
        };

        return e;
    }

    pub fn enforce(&self, rvals: Vec<String>) -> bool {
        let mut engine = Engine::new();
        let mut scope: Scope = Vec::new(); // rhai的作用域，保存求值需要用到的变量
                                           // let mut r_tokens: HashMap<String, usize> = HashMap::new();
        for (i, token) in self
            .model
            .model
            .get("r")
            .unwrap()
            .get("r")
            .unwrap()
            .tokens
            .iter()
            .enumerate()
        {
            // r_tokens.insert(token.clone(), i);
            engine
                .eval_with_scope::<()>(
                    &mut scope,
                    format!("let {} = \"{}\";", token.clone(), rvals[i]).as_str(),
                )
                .expect("set rtoken scope failed");
        }
        // 准备从字符串求值一个表达式

        for (key, func) in self.fm.iter() {
            engine.register_fn(key.as_str(), func.clone());
        }
        if let Some(g_result) = self.model.model.get("g") {
            for (key, ast) in g_result.iter() {
                let rm0 = ast.rm.clone();
                let f1 = generate_g_function(rm0);
                engine.register_fn(key.as_str(), f1.clone());
            }
        }
        let expstring = self
            .model
            .model
            .get("m")
            .unwrap()
            .get("m")
            .unwrap()
            .value
            .clone();
        let mut policy_effects: Vec<EffectKind> = vec![];
        let mut matcher_results: Vec<f64> = vec![];
        let policy_len = self
            .model
            .model
            .get("p")
            .unwrap()
            .get("p")
            .unwrap()
            .policy
            .len();
        if policy_len != 0 {
            if self
                .model
                .model
                .get("r")
                .unwrap()
                .get("r")
                .unwrap()
                .tokens
                .len()
                != rvals.len()
            {
                return false;
            }
            for (i, pvals) in self
                .model
                .model
                .get("p")
                .unwrap()
                .get("p")
                .unwrap()
                .policy
                .iter()
                .enumerate()
            {
                if self
                    .model
                    .model
                    .get("p")
                    .unwrap()
                    .get("p")
                    .unwrap()
                    .tokens
                    .len()
                    != pvals.len()
                {
                    return false;
                }
                // parameters.p_vals = pvals.clone();
                // let mut p_tokens: HashMap<String, usize> = HashMap::new();
                for (i, token) in self
                    .model
                    .model
                    .get("p")
                    .unwrap()
                    .get("p")
                    .unwrap()
                    .tokens
                    .iter()
                    .enumerate()
                {
                    // p_tokens.insert(token.clone(), i);
                    engine
                        .eval_with_scope::<()>(
                            &mut scope,
                            format!("let {} = \"{}\";", token.clone(), pvals[i]).as_str(),
                        )
                        .expect("set ptoken scope failed");
                }

                let eval_result = engine
                    .eval_with_scope::<bool>(&mut scope, expstring.as_str())
                    .expect("eval expression failed");
                if !eval_result {
                    policy_effects[i] = EffectKind::Indeterminate;
                    continue;
                }
                // TODO: p_tokens check
            }
        } else {
            for (i, token) in self
                .model
                .model
                .get("p")
                .unwrap()
                .get("p")
                .unwrap()
                .tokens
                .iter()
                .enumerate()
            {
                // p_tokens.insert(token.clone(), i);
                let _exp1 = format!("let {} = \"{}\";", token.clone(), "").as_str();
                engine
                    .eval_with_scope::<()>(
                        &mut scope,
                        format!("let {} = \"{}\";", token.clone(), "").as_str(),
                    )
                    .expect("set ptoken in else scope failed");
            }
            let eval_result = engine
                .eval_with_scope::<bool>(&mut scope, expstring.as_str())
                .expect("eval expression failed");
            if eval_result {
                policy_effects.push(EffectKind::Allow);
            } else {
                policy_effects.push(EffectKind::Indeterminate);
            }
        }

        // TODO: final result
        let ee = self
            .model
            .model
            .get("e")
            .unwrap()
            .get("e")
            .unwrap()
            .value
            .clone();
        let final_result = self.eft.merge_effects(ee, policy_effects, matcher_results);
        return final_result;
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

        let adapter = FileAdapter::new("../examples/keymatch_policy.csv");

        let enforcer = Enforcer::new(m, adapter);
        assert_eq!(
            true,
            enforcer.enforce(vec![
                "alice".to_owned(),
                "/alice_data/resource1".to_owned(),
                "GET".to_owned()
            ])
        );
    }
}
