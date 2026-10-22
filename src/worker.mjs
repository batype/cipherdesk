import { runTask } from "./core.mjs";
self.onmessage = async ({ data }) => {
  try {
    self.postMessage({ id: data.id, result: await runTask(data.job) });
  } catch (error) {
    self.postMessage({ id: data.id, error: error.message || "处理失败，请检查参数" });
  }
};
