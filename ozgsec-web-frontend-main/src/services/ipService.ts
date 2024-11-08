import { rabbitMQRPCClient } from "./rabbitmqClient";

const lookupNetwork = async (cidr: string, requestId: string) => {
  // does a fire and forget. The response will be sent to the queue "ip-lookup-response"
  return rabbitMQRPCClient.send(
    "ip-lookup",
    {
      cidr,
    },
    { durable: true, maxPriority: 10 },
    {
      messageId: requestId,
      replyTo: "ip-lookup-response",
    },
  );
};

export const ipService = {
  lookupNetwork,
};
