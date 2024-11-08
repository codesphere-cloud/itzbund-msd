import HttpError from "./HttpError";

export default class MethodNotAllowed extends HttpError {
  constructor() {
    super("MethodNotAllowed", 405, "Method Not Allowed");
  }
}
