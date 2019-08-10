use crate::rbac::{DefaultRoleManager, RoleManager};
use regex::Regex;
use std::collections::HashMap;

fn escape_assertion(s: String) -> String {
    let mut s = s;
    // TODO: 要按照正则来替换
    s = s.replacen(".", "_", 100);
    return s;
}

type AssertionMap = HashMap<String, Assertion>;

pub struct Assertion {
    pub key: String,
    pub value: String,
    pub tokens: Vec<String>,
    pub policy: Vec<Vec<String>>,
    pub rm: DefaultRoleManager,
}

impl Assertion {
    pub fn new() -> Self {
        return Assertion {
            key: String::new(),
            value: String::new(),
            tokens: vec![],
            policy: vec![],
            rm: DefaultRoleManager::new(0),
        };
    }

    // TODO: error handling
    pub fn build_role_links(&mut self, mut rm: DefaultRoleManager) {
        let count = self.value.chars().filter(|&c| c == '_').count();
        if count < 2 {
            panic!("the number of \"_\" in role definition should be at least 2")
        }
        for (_k, rule) in self.policy.iter().enumerate() {
            if rule.len() < count {
                panic!("grouping policy elements do not meet role definition")
            }
            if count == 2 {
                rm.add_link(rule[0].clone(), rule[1].clone(), None);
            } else if count == 3 {
                rm.add_link(
                    rule[0].clone(),
                    rule[1].clone(),
                    Some(vec![rule[2].clone()]),
                );
            } else if count == 4 {
                rm.add_link(
                    rule[0].clone(),
                    rule[1].clone(),
                    Some(vec![rule[2].clone(), rule[3].clone()]),
                );
            }
        }
        // return self.rm.print_roles();
        self.rm = rm;
    }
}

pub struct Model {
    // 包含模型定义，应该从配置文件读取，或者手动创建
    pub model: HashMap<String, AssertionMap>,
}

impl Model {
    pub fn new() -> Self {
        return Model {
            model: HashMap::new(),
        };
    }

    // TODO: key发生了borrow，可以考虑是否传引用
    pub fn add_def(&mut self, sec: &str, key: &str, value: &str) -> bool {
        let mut ast = Assertion::new();
        ast.key = key.to_owned();
        ast.value = value.to_owned();

        if ast.value == "" {
            return false;
        }

        if sec == "r" || sec == "p" {
            ast.tokens = ast.value.split(", ").map(String::from).collect();
            for i in 0..ast.tokens.len() {
                ast.tokens[i] = format!("{}_{}", key.clone(), ast.tokens[i]);
            }
        } else {
            // 先做正则，把点号替换掉
            ast.value = escape_assertion(ast.value);
        }

        // 从model取sec
        if let Some(new_model) = self.model.get_mut(sec) {
            new_model.insert(key.to_owned(), ast);
        } else {
            let mut new_ast_map = HashMap::new();
            new_ast_map.insert(key.to_owned(), ast);
            self.model.insert(sec.to_owned(), new_ast_map);
        }

        return true;
    }
}

pub type FunctionMap = HashMap<String, fn(String, String) -> bool>;

pub fn load_function_map() -> FunctionMap {
    let mut fm: HashMap<String, fn(String, String) -> bool> = HashMap::new();
    fm.insert("keyMatch".to_owned(), key_match);
    fm.insert("keyMatch2".to_owned(), key_match2);
    fm.insert("regexMatch".to_owned(), regex_match);
    return fm;
}

fn key_match(key1: String, key2: String) -> bool {
    if let Some(i) = key2.find("*") {
        if key1.len() > i {
            return &key1[i..i] == &key2[..i];
        }
        return &key1[..] == &key2[..i];
    } else {
        return key1 == key2;
    }
}

fn key_match_func(args: Vec<String>) -> bool {
    let name1 = args[0].clone();
    let name2 = args[1].clone();
    return key_match(name1, name2);
}

fn key_match2(key1: String, key2: String) -> bool {
    let mut key2 = key2.replace("/*", "/.*");
    let re = Regex::new("(.*):[^/]+(.*)").unwrap();
    loop {
        if key2.contains("/:") {
            break;
        }
        key2 = re.replace_all(key2.as_str(), "$1[^/]+$2").to_string();
    }
    return regex_match(key1, format!("^{}$", key2));
}

fn key_match2_func(args: Vec<String>) -> bool {
    let name1 = args[0].clone();
    let name2 = args[1].clone();
    return key_match2(name1, name2);
}

// fn key_match3(key1: String, key2: String) -> bool {
//     let mut key2 = key2.replace("/*", "/.*");
//     let re = Regex::new(r"(.*)\{[^/]+\}(.*)").unwrap();
//     loop {
//         if key2.contains("/{") {
//             break;
//         }
//         key2 = re.replace_all(key2.as_str(), "$1[^/]+$2").to_string();
//     }
//     return regex_match(key1, format!("^{}$", key2));
// }

// fn key_match3_func(args: Vec<String>) -> bool {
//     let args = args.unwrap();
//     let name1 = args[0].clone();
//     let name2 = args[1].clone();
//     return key_match3(name1, name2);
// }

fn regex_match(key1: String, key2: String) -> bool {
    return Regex::new(key2.as_str()).unwrap().is_match(key1.as_str());
}

fn regex_match_func(args: Vec<String>) -> bool {
    let name1 = args[0].clone();
    let name2 = args[1].clone();
    return regex_match(name1, name2);
}
