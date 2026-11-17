const api = require('../../utils/api');

const CAT_CN = { ACCOUNT: '账户', LOAN: '贷款', CREDIT_CARD: '信用卡', OTHER: '其他' };
const ST_CN = {
  SUBMITTED: '已受理，处理中', AI_ANSWERING: 'AI 应答中', CLOSED_AI: 'AI 已回复',
  PENDING_HUMAN: '待人工接管', HUMAN_ANSWERING: '人工处理中', CLOSED_HUMAN: '已办结'
};

Page({
  data: {
    fbId: '',
    ticket: null,
    stText: '',
    catText: '',
    replies: [],
    body: '',
    canAppend: false,
    canRate: false,
    sending: false,
    rated: false
  },
  onLoad(query) {
    this.setData({ fbId: query.fb || '' });
  },
  onShow() {
    this.refresh();
    this.timer = setInterval(() => this.refresh(true), 5000);
  },
  onUnload() {
    if (this.timer) clearInterval(this.timer);
  },
  refresh(silent) {
    if (!this.data.fbId) return;
    api.query(this.data.fbId).then((d) => {
      const replies = d.replies || [];
      const closed = d.status === 'CLOSED_AI' || d.status === 'CLOSED_HUMAN';
      this.setData({
        ticket: d,
        stText: ST_CN[d.status] || d.status,
        catText: CAT_CN[d.category] || d.category,
        replies: replies,
        canAppend: !closed,
        // AI 会话中（AI_ANSWERING）即可评价办结；人工流程待办结后评价
        canRate: !this.data.rated && (d.status === 'AI_ANSWERING' || closed)
      });
      if (!silent) {
        wx.pageScrollTo({ scrollTop: 99999, duration: 0 });
      }
    }).catch((e) => {
      if (!silent) wx.showModal({ title: '加载失败', content: e.message, showCancel: false });
    });
  },
  onInput(e) {
    this.setData({ body: e.detail.value });
  },
  async send() {
    const body = this.data.body.trim();
    if (!body || !this.data.canAppend) return;
    this.setData({ sending: true });
    try {
      await api.append(this.data.fbId, body);
      this.setData({ body: '' });
      this.refresh();
    } catch (e) {
      wx.showModal({ title: '发送失败', content: e.message, showCancel: false });
    } finally {
      this.setData({ sending: false });
    }
  },
  async rate(e) {
    const v = e.currentTarget.dataset.v === 'good' ? 1 : 0;
    try {
      await api.rate(this.data.fbId, v);
      this.setData({ rated: true, canRate: false });
      wx.showToast({ title: '感谢您的评价', icon: 'success' });
    } catch (err) {
      wx.showModal({ title: '评价失败', content: err.message, showCancel: false });
    }
  }
});
