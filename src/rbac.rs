pub trait RoleManager {
    fn clear(&mut self);
    fn add_link(&mut self, name1: String, name2: String, domain: Option<Vec<String>>);
    fn delete_link(&mut self, name1: String, name2: String, domain: Option<Vec<String>>);
    fn has_link(&self, name1: String, name2: String, domain: Option<Vec<String>>) -> bool;
    fn get_roles(&self, name: String, domain: Option<Vec<String>>) -> Vec<String>;
    fn get_users(&self, name: String, domain: Option<Vec<String>>) -> Vec<String>;
    fn print_roles(&self);
}

use std::collections::HashMap;

type MatchingFunc = fn(String, String) -> bool;

pub struct DefaultRoleManager {
    pub all_roles: HashMap<String, Role>,
    pub max_hierarchy_level: usize,
    pub has_pattern: bool,
    pub matching_func: Option<MatchingFunc>,
}

impl DefaultRoleManager {
    pub fn new(max_hierarchy_level: usize) -> Self {
        return DefaultRoleManager {
            all_roles: HashMap::new(),
            max_hierarchy_level,
            has_pattern: false,
            matching_func: None,
        };
    }

    fn create_role(&mut self, name: String) -> Role {
        // TODO: 加上 has_pattern 判断
        let role = self
            .all_roles
            .entry(name.clone())
            .or_insert(Role::new(name.clone()))
            .clone();
        return role;
    }

    fn has_role(&self, name: String, hierarchyLevel: Option<usize>) -> bool {
        // TODO: 添加完整实现
        return true;
    }
}

impl RoleManager for DefaultRoleManager {
    fn add_link(&mut self, name1: String, name2: String, domain: Option<Vec<String>>) {
        let mut name1 = name1;
        let mut name2 = name2;
        if !domain.is_none() {
            let domain = domain.unwrap();
            if domain.len() == 1 {
                name1 = format!("{}::{}", domain[0], name1);
                name2 = format!("{}::{}", domain[0], name2);
            } else if domain.len() > 1 {
                panic!("error domain length");
            }
        }
        let mut role1 = self.create_role(name1);
        let role2 = self.create_role(name2);
        role1.add_role(role2);
    }

    fn delete_link(&mut self, name1: String, name2: String, domain: Option<Vec<String>>) {
        let mut name1 = name1;
        let mut name2 = name2;
        if !domain.is_none() {
            let domain = domain.unwrap();
            if domain.len() == 1 {
                name1 = format!("{}::{}", domain[0], name1);
                name2 = format!("{}::{}", domain[0], name2);
            } else if domain.len() > 1 {
                panic!("error domain length");
            }
        }
        if !self.has_role(name1.clone(), None) || !self.has_role(name2.clone(), None) {
            panic!("name12 error");
        }
        let mut role1 = self.create_role(name1.clone());
        let role2 = self.create_role(name2.clone());
        role1.delete_role(role2);
    }

    fn has_link(&self, name1: String, name2: String, domain: Option<Vec<String>>) -> bool {
        return true;
    }

    fn get_roles(&self, name: String, domain: Option<Vec<String>>) -> Vec<String> {
        return vec![];
    }

    fn get_users(&self, name: String, domain: Option<Vec<String>>) -> Vec<String> {
        return vec![];
    }

    fn print_roles(&self) {
        println!("print_roles tbd");
    }

    fn clear(&mut self) {
        // TODO: 清空当前对象
        self.all_roles = HashMap::new();
    }
}

#[derive(Clone)]
pub struct Role {
    pub name: String,
    pub roles: Vec<Box<Role>>,
}

impl Role {
    pub fn new(name: String) -> Self {
        return Role {
            name,
            roles: vec![],
        };
    }

    pub fn add_role(&mut self, other_role: Role) {
        for old_role in self.roles.iter() {
            if old_role.name == other_role.name {
                return;
            }
        }
        self.roles.push(Box::new(other_role));
    }

    fn delete_role(&mut self, other_role: Role) {
        if let Some(pos) = self
            .roles
            .iter()
            .cloned()
            .position(|x| x.name == other_role.name)
        {
            self.roles.remove(pos);
        }
    }
}
