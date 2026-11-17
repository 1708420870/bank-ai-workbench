const api = require('../../utils/api');

Page({
  data: {
    items: [],
    queryId: ''
  },
  onShow() {
    this.refresh();
  },
  refresh() {
    const list = wx.getStorageSync('fb_list') || [];
    const items = [];
    let done = 0;
    const next = () => {
      this.setData({ items });
    };
    if (!list.length) { next(); return; }
    list.forEach((fb) => {
      api.query(fb).then((d) => {
        items.push(d);
        done += 1;
        if (done === list.length) next();
      }).catch(() => {
        items.push({ fb_id: fb, status: 'UNKNOWN', category: '-', replies: [] });
        done += 1;
        if (done === list.length) next();
      });
    });
  },
  onQueryInput(e) {
    this.setData({ queryId: e.detail.value });
  },
  queryOne() {
    const id = this.data.queryId.trim();
    if (!id) return;
    api.query(id).then((d) => {
      const list = wx.getStorageSync('fb_list') || [];
      if (!list.includes(id)) {
        list.unshift(id);
        wx.setStorageSync('fb_list', list);
      }
      wx.navigateTo({ url: '/pages/chat/chat?fb=' + id });
    }).catch((e) => {
      wx.showModal({ title: '查询失败', content: e.message, showCancel: false });
    });
  },
  open(e) {
    wx.navigateTo({ url: '/pages/chat/chat?fb=' + e.currentTarget.dataset.fb });
  }
});
