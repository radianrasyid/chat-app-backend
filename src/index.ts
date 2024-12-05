import { cors } from "@elysiajs/cors";
import { jwt } from "@elysiajs/jwt";
import { ServerWebSocket } from "bun";
import { Elysia, t } from "elysia";
import { ElysiaWS } from "elysia/dist/ws";
import logixlysia from "logixlysia";
import { db } from "./lib/utils/db";
import { encryptMessage, generateKeyPair } from "./lib/utils/messaging";

interface ClientInfo {
  id: string;
  username: string;
  socket: ElysiaWS<ServerWebSocket<any>, any, any>;
  publicKey: string;
  privateKey: string;
}

const clients = new Map<string, ClientInfo>();

const app = new Elysia()
  .use(cors())
  .use(
    logixlysia({
      config: {
        showStartupMessage: true,
        startupMessageFormat: "simple",
        timestamp: {
          translateTime: "yyyy-mm-dd HH:MM:ss",
        },
        ip: true,
        logFilePath: "../logs/runtime.log",
        customLogFormat:
          "🦊 {now} {level} {duration} {method} {pathname} {status} {message} {ip} {epoch}",
        logFilter: {
          // level: ["ERROR", "WARNING"],
          // status: [500, 404],
          // method: 'GET'
        },
      },
    })
  )
  .use(
    jwt({
      name: "auth_jwt",
      secret: "r4d14nr45y1d",
      schema: t.Object({
        id: t.String(),
      }),
    })
  )
  .get("/", () => "Hello from radtech")
  .post(
    "/register",
    async ({ set, body }) => {
      const hashedPassword = Bun.password.hashSync(body.password);

      const { publicKey, privateKey } = await generateKeyPair();

      const user = await db.user.create({
        data: {
          username: body.username,
          password: hashedPassword,
          publicKey,
          privateKey,
        },
      });

      set.status = 200;
      return {
        message: "User successfully created",
        data: user,
      };
    },
    {
      body: t.Object({
        username: t.String({
          minLength: 3,
        }),
        password: t.String({ minLength: 8 }),
      }),
      error: ({ error }) => error.message,
    }
  )
  .post(
    "/login",
    async ({ set, body, auth_jwt, cookie: { auth_cookie } }) => {
      const found = await db.user.findUnique({
        where: {
          username: body.username,
        },
      });

      if (found == null) {
        set.status = 400;
        return {
          message: "username or password might be wrong",
        };
      }

      const isPasswordMatch = Bun.password.verifySync(
        body.password,
        found.password
      );

      if (!isPasswordMatch) {
        set.status = 400;
        return {
          message: "username or password might be wrong",
        };
      }

      const jwt = await auth_jwt.sign({
        id: found.id,
      });

      set.status = 200;
      auth_cookie.set({
        value: jwt,
        httpOnly: true,
      });
      set.cookie = {
        auth_cookie,
      };
      return {
        message: "Login success",
        data: {
          jwt,
          privateKey: found.privateKey,
          publicKey: found.publicKey,
        },
      };
    },
    {
      body: t.Object({
        username: t.String(),
        password: t.String(),
      }),
    }
  )
  .get(
    "/users/:username",
    async ({
      set,
      params: { username },
      query: { page = 1, pageSize = 10 },
    }) => {
      const skip = (Number(page) - 1) * Number(pageSize);
      const take = Number(pageSize);
      const [data, totalCount] = await Promise.all([
        db.user.findMany({
          where: {
            username: {
              contains: username, // Use contains for partial matches if needed
            },
          },
          select: {
            username: true,
            id: true,
            publicKey: true,
          },
          skip,
          take,
        }),
        db.user.count({
          where: {
            username: {
              contains: username,
            },
          },
        }),
      ]);

      set.status = 200;
      return {
        message: "user list",
        data: data,
        meta: {
          currentPage: page,
          pageSize,
          totalPages: Math.ceil(totalCount / Number(pageSize)),
          totalCount,
        },
      };
    }
  )
  .ws("/ws", {
    open: async (ws) => {
      const jwt = ws.data.cookie["auth_cookie"].value;
      const userId = await ws.data.auth_jwt.verify(jwt);
      console.log("connection opened", userId);

      if (userId == false) {
        ws.close();
        return;
      }

      // First, ensure clients map exists in the store
      const user = await db.user.findUnique({
        where: {
          id: userId.id,
        },
        select: {
          id: true,
          username: true,
          publicKey: true,
          privateKey: true,
        },
      });

      if (user == null) {
        ws.close();
        return;
      }

      clients.set(user.id, {
        id: user.id,
        socket: ws,
        username: user.username,
        publicKey: user.publicKey,
        privateKey: user.privateKey,
      });

      console.log(
        "current client",
        Array.from(clients.values()).map((i) => i.id)
      );
    },
    message: async (ws, message) => {
      console.log(
        "current client",
        Array.from(clients.values()).map((i) => i.id)
      );
      const jwt = ws.data.cookie["auth_cookie"].value;
      const userId = await ws.data.auth_jwt.verify(jwt);
      if (userId == false) {
        ws.close();
        return;
      }
      message.from = userId.id;
      console.log("received message", message);
      const sender = clients.get(userId.id);
      const recipient = clients.get(message.to);
      if (sender?.id === recipient?.id) {
        sender?.socket.send(
          JSON.stringify({
            from: "",
            to: "",
            code: 3,
            message: "can not send message to yourself at this version",
          })
        );
        return;
      }

      if (sender && recipient) {
        const encryptedMessage = await encryptMessage(
          recipient.publicKey,
          message.message
        );
        console.log("ini encrypted message", encryptedMessage);
        recipient.socket.send(
          JSON.stringify({
            from: sender.id,
            to: recipient.id,
            code: 1,
            message: encryptedMessage,
            encrypted: true,
            publicKey: recipient.publicKey,
            privateKey: recipient.privateKey,
          })
        );
        sender.socket.send(
          JSON.stringify({
            from: sender.id,
            to: recipient.id,
            code: 0,
            message: encryptedMessage,
            encrypted: true,
            publicKey: recipient.publicKey,
            privateKey: recipient.privateKey,
          })
        );
      }
    },
    close: (ws, code, message) => {},
    body: t.Union([
      t.Object({
        to: t.String(),
        from: t.String(),
        message: t.String(),
      }),
    ]),
  })
  .listen(3000);
