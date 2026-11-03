import React from "react";

export default class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error, info) {
    console.error("render error:", error, info);
  }

  render() {
    if (this.state.error) {
      return (
        <div className="error-screen">
          <div className="error-title">页面渲染出错了</div>
          <pre className="error-detail">{String(this.state.error?.stack || this.state.error)}</pre>
          <button className="plain-btn" onClick={() => this.setState({ error: null })}>
            重试
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
