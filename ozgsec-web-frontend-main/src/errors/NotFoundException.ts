import HttpError from "./HttpError";

export default class NotFoundException extends HttpError {
  constructor() {
    super("NotFoundException", 404, "Not Found");
  }
}
