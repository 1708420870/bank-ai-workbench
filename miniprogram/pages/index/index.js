const api = require('../../utils/api');

const CATS = [
  { key: 'ACCOUNT', name: '账户业务' },
  { key: 'LOAN', name: '贷款业务' },
  { key: 'CREDIT_CARD', name: '信用卡' },
  { key: 'OTHER', name: '其他' }
];

Page({
  data: {
    cats: CATS,
    catIndex: 0,
    body: '',
    maxLen: 500,
    submitting: false,
    gateway: api.getGateway()
  },
  onCatChange(e) {
    this.setData({ catIndex: Number(e.detail.value) });
  },
  onInput(e) {
    this.setData({ body: e.detail.value });
  },
  async submit() {
    const body = this.data.body.trim();
    if (!body) {
      wx.showToast({ title: '请填写反馈内容', icon: 'none' });
      return;
    }
    this.setData({ submitting: true });
    try {
      const d = await api.submit(CATS[this.data.catIndex].key, body);
      // 记录到本机反馈列表
      const list = wx.getStorageSync('fb_list') || [];
      if (!list.includes(d.fb_id)) list.unshift(d.fb_id);
      wx.setStorageSync('fb_list', list);
      wx.showToast({ title: '提交成功', icon: 'success' });
      this.setData({ body: '' });
      wx.navigateTo({ url: '/pages/chat/chat?fb=' + d.fb_id });
    } catch (e) {
      wx.showModal({ title: '提交失败', content: e.message, showCancel: false });
    } finally {
      this.setData({ submitting: false });
    }
  },
  goList() {
    wx.navigateTo({ url: '/pages/tickets/tickets' });
  }
});
