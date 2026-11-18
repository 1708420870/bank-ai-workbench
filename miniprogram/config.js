// 反馈网关地址集中配置：换机器、换环境只改这一个文件，不再改 app.js。
//
// 三种环境对应三种用法：
//   localhost  本机开发者工具演示（小程序与后端在同一台电脑）
//   lan        真机预览：手机和电脑连同一 Wi-Fi，填电脑的局域网 IP
//   public     正式/体验版：必须是已备案的 HTTPS 域名，并在 mp.weixin.qq.com
//              「开发管理-开发设置-服务器域名」里配到 request 合法域名
//
// 现场临时换地址不必改代码：开发者工具 Console 里执行
//   wx.setStorageSync('gateway_override', 'http://192.168.1.5:8103')
// 清掉用 wx.removeStorageSync('gateway_override')。app.js 会优先读这个覆盖值。
const ENV = 'lan'

const PRESETS = {
  localhost: 'http://127.0.0.1:8103',
  // ↓ 换成运行「启动-局域网.bat」那台电脑的局域网 IP（程序启动时会打印出来）
  lan: 'http://10.99.224.207:8103',
  public: 'https://feedback.example.com'
}

module.exports = {
  env: ENV,
  gateway: PRESETS[ENV] || PRESETS.lan,
  presets: PRESETS
}
