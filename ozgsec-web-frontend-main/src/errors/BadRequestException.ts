import HttpError from "./HttpError";

export default class BadRequestException extends HttpError {
  constructor(msg = "Bad Request") {
    super("BadRequestException", 400, msg);
  }
}
