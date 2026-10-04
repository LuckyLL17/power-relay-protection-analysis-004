# 电网继电保护动作分析与故障定位服务

纯后端 Node.js + TypeScript + Fastify 服务，无需 Docker、数据库或消息中间件即可本机运行。

## 复杂业务闭环

- 变电站、线路、断路器、保护装置和拓扑版本
- 录波采样质量检查与统一毫秒时间轴
- 短路类型、序分量和视在阻抗计算
- 故障距离、区段和置信度定位
- 保护动作序列重放、选择性判断、拒动/后备保护识别
- 定值版本校验、设备检修试验和分析审批
- 故障事件、录波、拓扑变更与审批审计追踪
- 故障证据包：按事件时刻截取快照、规范化指纹、封存与校验

默认端口：`6311`。

## 模块结构

- `src/domain`：领域类型、坐标/单位约束和进程内状态锚点
- `src/services`：计算、仿真、融合和风险规则
- `src/routes`：按业务边界拆分的 HTTP 接口
- `src/app.ts`：应用组装与路由注册
- `src/index.ts`：进程启动入口

各模块保持单一职责，业务状态只由 domain state 模块持有，避免路由之间重复维护同一份状态。

## 故障证据包（跨班组移交）

调度/保护班组把一次故障的事件、录波、事件时刻拓扑、保护定值、动作序列和审计记录打包给另一班组时，
直接读当前内存会受后续变更影响。证据包按事件时刻截取**值拷贝快照**，规范化（键序确定的 JSON）后计算
SHA-256 总指纹与六个分段指纹；封存后整包深度冻结，源数据变化不会改写包，只会在校验中以来源漂移显式暴露。

- `POST /api/fault-events/:id/evidence-package`：生成（重复创建幂等，响应头 `X-Evidence-Reused: true`）
- `GET  /api/evidence-packages` / `GET /api/evidence-packages/:id`：列表 / 取回只读包
- `POST /api/evidence-packages/:id/seal`：封存（幂等）
- `POST /api/evidence-packages/:id/verify`：指纹一致性 + 封存后来源漂移校验

生成失败必须显式报错：`event-not-found`(404)、`analysis-missing`(422)、
`recording-missing`(422)、`source-after-event`(422，录波来源晚于事件时刻)。

校验：`npm run verify:evidence`（完整生成、缺失来源、封存后变化、重复创建、指纹不一致）。
