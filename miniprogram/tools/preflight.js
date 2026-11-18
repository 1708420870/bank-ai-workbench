#!/usr/bin/env node
/**
 * 小程序上线前自检（发包/提审前手工门禁）
 *
 *   node miniprogram/tools/preflight.js
 *
 * 只做静态检查，不联网、不改文件。任一 P0 项不通过则退出码 1。
 * 开发阶段运行预期为「不通过」，这是正常状态——它检查的正是"是否已经具备上线条"。
 */
const fs = require('fs')
const path = require('path')

const ROOT = path.resolve(__dirname, '..')
const read = (p) => fs.readFileSync(path.join(ROOT, p), 'utf8')
const readJson = (p) => JSON.parse(read(p))

const results = []
const add = (level, item, ok, detail) => results.push({ level, item, ok, detail })

// ---------- P0：不提审就过不去的 ----------
let config = {}
try {
  config = require(path.join(ROOT, 'config.js'))
} catch (e) {
  add('P0', 'config.js 可加载', false, e.message)
}

if (config.env !== undefined) {
  add('P0', '网关环境已切 public', config.env === 'public',
    `当前 ENV='${config.env}'，提审前须改为 'public'`)
}
if (config.gateway) {
  const https = String(config.gateway).startsWith('https://')
  add('P0', '网关为 HTTPS', https,
    https ? config.gateway : `当前 ${config.gateway}；微信 request 只接受 HTTPS`)
}

let project = {}
try {
  project = readJson('project.config.json')
} catch (e) {
  add('P0', 'project.config.json 可解析', false, e.message)
}
if (project.setting) {
  add('P0', '已开启域名校验（urlCheck）', project.setting.urlCheck === true,
    project.setting.urlCheck === true ? '已开启' : '当前 false；上线版必须开启，否则审核不通过')
}
if (project.appid !== undefined) {
  const bad = !project.appid || project.appid === 'touristappid'
  add('P0', 'AppID 非空且非测试号', !bad, bad ? '为占位/测试号，需换本单位正式 AppID' : project.appid)
}

// 隐私合规：微信后台需填《用户隐私保护指引》，代码里建议有可访问的隐私页
let appJson = {}
try {
  appJson = readJson('app.json')
} catch (e) {
  add('P1', 'app.json 可解析', false, e.message)
}
const pages = (appJson.pages || []).join(' ')
add('P1', '存在隐私政策页面', /privacy|policy|隐私/.test(pages),
  '未检测到隐私页；后台《用户隐私保护指引》必须填写，建议页面同步提供入口')

// ---------- P1/P2：上线前应清理的 ----------
const appJs = read('app.js')
add('P1', '已移除运行时地址覆盖开关', !appJs.includes('gateway_override'),
  'gateway_override 便于现场调试，但生产版应删掉，避免被改指向')

const jsFiles = ['app.js', 'config.js', 'utils/api.js']
  .concat((appJson.pages || []).map((p) => p + '.js'))
  .filter((p) => fs.existsSync(path.join(ROOT, p)))
let logCount = 0
jsFiles.forEach((f) => {
  const m = read(f).match(/console\.(log|debug|info)\s*\(/g)
  if (m) logCount += m.length
})
add('P2', '调试输出已收敛', logCount <= 1,
  `检测到 ${logCount} 处 console.log/debug；生产建议保留 0–1 处`)

add('P2', 'project.private.config.json 不入库', !fs.existsSync(path.join(ROOT, 'project.private.config.json')),
  '该文件是本机私有设置，提审前确认未被随代码包带走')

// ---------- 输出 ----------
const icon = (r) => (r.ok ? '  OK ' : (r.level === 'P0' ? ' FAIL' : ' WARN'))
const width = 34
console.log('')
console.log('小程序上线前自检')
console.log('='.repeat(78))
results.forEach((r) => {
  console.log(`${icon(r)}  [${r.level}] ${r.item.padEnd(width - 8)} ${r.detail}`)
})
console.log('='.repeat(78))

const failed = results.filter((r) => !r.ok && r.level === 'P0')
const warned = results.filter((r) => !r.ok && r.level !== 'P0')
console.log(`P0 未通过 ${failed.length} 项，提示 ${warned.length} 项`)
if (failed.length) {
  console.log('结论：尚不具备提审条件（开发版属正常状态）。逐条处置见 docs/26。')
  process.exit(1)
}
console.log('结论：P0 全部通过，可进入提审。请再人工核对资质与备案状态（docs/26 第二节）。')
