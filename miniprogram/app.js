// 银行客服 AI 工作台 · 客户反馈小程序
const config = require('./config.js')

App({
  onLaunch() {
    // 客户身份：PoC 用本地生成的稳定伪 openid（生产应替换为 wx.login code2session
    // 换取的真实 openid，由行方后端完成换取，前端永不接触密钥）
    let openid = wx.getStorageSync('fb_openid');
    if (!openid) {
      openid = 'oPoc-' + Date.now() + '-' + Math.random().toString(36).slice(2, 10);
      wx.setStorageSync('fb_openid', openid);
    }
    this.globalData.openid = openid;

    // 网关地址：config.js 里的预设优先，其次读取现场临时覆盖值。
    // 覆盖值让演示时不必改代码——见 config.js 顶部说明。
    const override = wx.getStorageSync('gateway_override');
    this.globalData.gateway = override || config.gateway;
    console.log('[gateway]', this.globalData.gateway, 'env=' + config.env,
      override ? '(来自 gateway_override 覆盖)' : '');
  },
  globalData: {
    openid: '',
    // 实际值由 onLaunch 依据 config.js 写入，此处只作兜底
    gateway: config.gateway
  }
});
