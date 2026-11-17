// 反馈网关 API 封装
const app = getApp();

function request(path, method, data) {
  return new Promise((resolve, reject) => {
    wx.request({
      url: app.globalData.gateway + path,
      method: method || 'GET',
      data: data || {},
      timeout: 35000,
      success(res) {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve(res.data);
        } else {
          const detail = (res.data && res.data.detail) || ('HTTP ' + res.statusCode);
          reject(new Error(detail));
        }
      },
      fail(err) {
        reject(new Error('网络不可达：请确认工作台已启动，且已在开发者工具中勾选「不校验合法域名」'));
      }
    });
  });
}

module.exports = {
  getOpenid() { return app.globalData.openid; },
  getGateway() { return app.globalData.gateway; },
  submit(category, body) {
    return request('/feedback/api/v1/tickets', 'POST',
      { openid: app.globalData.openid, category: category, body: body });
  },
  query(fbId) {
    return request('/feedback/api/v1/tickets/' + fbId + '?openid=' +
      encodeURIComponent(app.globalData.openid));
  },
  append(fbId, body) {
    return request('/feedback/api/v1/tickets/' + fbId + '/messages', 'POST',
      { openid: app.globalData.openid, body: body });
  },
  rate(fbId, value) {
    return request('/feedback/api/v1/tickets/' + fbId + '/messages', 'POST',
      { openid: app.globalData.openid, body: String(value), kind: 'eval' });
  }
};
