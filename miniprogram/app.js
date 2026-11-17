// 银行客服 AI 工作台 · 客户反馈小程序
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
  },
  globalData: {
    openid: '',
    // 反馈网关地址（外区 8103）。开发者工具演示：本机直连；
    // 真机预览改成开发机的局域网 IP（如 http://192.168.x.x:8103），
    // 并在开发者工具「详情-本地设置」勾选「不校验合法域名」。
    gateway: 'http://10.99.224.207:8103'
  }
});
