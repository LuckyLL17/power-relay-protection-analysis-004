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
- 故障证据包：按事件时刻截取事件、录波、拓扑、定值、动作序列与审计快照，生成规范化只读内容与 SHA-256 指纹，支持封存与校验；缺少分析、录波不存在或来源晚于事件时明确失败，重复创建幂等，封存后源数据变化在校验中明确报漂移且不改包

证据包接口：`POST /api/evidence-packages`（按 eventId 封存，幂等）、`GET /api/evidence-packages`、`GET /api/evidence-packages/:id`、`POST /api/evidence-packages/:id/verify`。场景验证：`npm run verify:evidence`。

默认端口：`6311`。

## 模块结构

- `src/domain`：领域类型、坐标/单位约束和进程内状态锚点
- `src/services`：计算、仿真、融合和风险规则
- `src/routes`：按业务边界拆分的 HTTP 接口
- `src/app.ts`：应用组装与路由注册
- `src/index.ts`：进程启动入口

各模块保持单一职责，业务状态只由 domain state 模块持有，避免路由之间重复维护同一份状态。
