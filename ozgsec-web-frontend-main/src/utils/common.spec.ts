import {
  isAdmin,
  isProgressMessage,
  limitStringValues,
  sanitizeURI,
  splitLineBreak,
} from "./common";

describe("common test suite", () => {
  it("should respect windows line breaks inside a csv file", () => {
    const data = `domain1.com\r\ndomain2.com`;
    const entries = splitLineBreak(data);
    expect(entries[0]).toEqual("domain1.com");
    expect(entries[1]).toEqual("domain2.com");
  });

  it("should respect unix line breaks inside a csv file", () => {
    const data = `domain1.com\ndomain2.com`;
    const entries = splitLineBreak(data);
    expect(entries[0]).toEqual("domain1.com");
    expect(entries[1]).toEqual("domain2.com");
  });

  it("should respect /r line breaks inside a csv file", () => {
    const data = `domain1.com\rdomain2.com`;
    const entries = splitLineBreak(data);
    expect(entries[0]).toEqual("domain1.com");
    expect(entries[1]).toEqual("domain2.com");
  });

  it("should remove leading and trailing white spaces", () => {
    const data = `domain1.com\ndomain2.com `;
    const entries = splitLineBreak(data);
    expect(entries[0]).toEqual("domain1.com");
    expect(entries[1]).toEqual("domain2.com");
  });

  it("should correctly identify a progress message", () => {
    expect(isProgressMessage({ queued: 10 })).toBe(true);
    expect(isProgressMessage({ completed: 5 })).toBe(false);
  });

  describe("should limit the string values of an object to the specified character length", () => {
    it("should work with null", () => {
      expect(limitStringValues(null, 10)).toBeNull();
    });
    it("should work with undefined", () => {
      expect(limitStringValues(undefined, 10)).toBeUndefined();
    });
    it("should work with an empty object", () => {
      expect(limitStringValues({}, 10)).toEqual({});
    });
    it("should work with a simple object", () => {
      expect(limitStringValues({ a: "1234567890" }, 2)).toEqual({
        a: "12",
      });
    });
    it("should work with a nested object", () => {
      expect(limitStringValues({ a: { b: "1234567890" } }, 2)).toEqual({
        a: { b: "12" },
      });
    });
    it("should work with an array", () => {
      expect(limitStringValues({ a: ["1234567890"] }, 2)).toEqual({
        a: ["12"],
      });
    });
    it("should work with a nested array", () => {
      expect(limitStringValues({ a: { b: ["1234567890"] } }, 2)).toEqual({
        a: { b: ["12"] },
      });
    });
  });

  describe("it should correctly identify users as admin based on the provided session", () => {
    it("should return false, if the session is null or undefined", () => {
      expect(isAdmin(null)).toBe(false);
      expect(isAdmin(undefined)).toBe(false);
    });
    it("should return false, if the session does not contain a resource_access object", () => {
      expect(isAdmin({} as any)).toBe(false);
    });
    it("should return false, if the resource_access realm management does not contain the role realm-admin", () => {
      expect(
        isAdmin({
          realm_access: {
            roles: ["notadmin"],
          },
        } as any),
      ).toBe(false);
    });
    it("should return true, if the resource_access realm management contains the role realm-admin", () => {
      expect(
        isAdmin({
          realmAccess: {
            roles: ["admin"],
          },
        } as any),
      ).toBe(true);
    });
  });
  describe("sanitize test suite", () => {
    it("should throw an error, if the input is not a string", () => {
      expect(sanitizeURI(123 as any)).toEqual(null);
    });
    it("should remove any protocol if provided", () => {
      expect(sanitizeURI("https://example.com")).toBe("example.com");
    });
    it("should remove any path if provided", () => {
      expect(sanitizeURI("example.com/path")).toBe("example.com/path");
    });
    it("should remove any query parameters if provided", () => {
      expect(sanitizeURI("example.com?query=param")).toBe("example.com");
    });
    it("should remove any hash if provided", () => {
      expect(sanitizeURI("example.com#hash")).toBe("example.com");
    });
    it("should remove any port if provided and reject ips", () => {
      expect(sanitizeURI("192.168.0.1:8080")).toBeNull;
    });
    it("should work for subdomains", () => {
      expect(sanitizeURI("subdomain.example.com")).toBe(
        "subdomain.example.com",
      );
    });
    it("should work if blank characters are present", () => {
      expect(sanitizeURI(" example.com ")).toBe("example.com");
    });
  });
});
