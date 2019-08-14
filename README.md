# casbin-rs

[![Build Status](https://travis-ci.org/xcaptain/casbin-rs.svg?branch=master)](https://travis-ci.org/xcaptain/casbin-rs)
[![codecov](https://codecov.io/gh/xcaptain/casbin-rs/branch/master/graph/badge.svg)](https://codecov.io/gh/xcaptain/casbin-rs)

用rust实现的一个casbin，目前正在大力开发中

## 如何测试

```shell
cargo test
```

如果使用vscode并且安装了lldb扩展的话，可以直接按下`F5`运行测试用例，并且添加断点调试代码

## TODO

- [x] 基本的匹配功能
- [ ] 从conf文件中创建model
- [x] rbac匹配
- [x] rbac构建角色链
- [ ] 错误处理
- [x] Enforcer中effector, adapter做成trait
- [x] Enforcer中role manager做成trait
- [ ] 一个postgresql的adapter
- [ ] 调研rhai，使得能够求值变参函数
