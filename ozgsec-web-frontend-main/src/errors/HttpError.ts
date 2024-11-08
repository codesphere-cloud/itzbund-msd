import { NextResponse } from "next/server";

export default class HttpError extends Error {
  public status: number;
  public message: string;
  public name: string;

  public redirectUrl = "/";
  constructor(name: string, status: number, message: string) {
    super(message);
    this.status = status;
    this.message = message;
    this.name = name;
  }

  toNextResponse(): NextResponse {
    return NextResponse.json(
      {
        name: this.name,
        message: this.message,
      },
      { status: this.status },
    );
  }
}
