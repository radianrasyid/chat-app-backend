import { db } from "../lib/utils/db";

async function CreateUser(props: {
  username: string;
  password: string;
  privateKey: string;
  publicKey: string;
}) {
  return await db.user.create({
    data: {
      ...props,
    },
  });
}

async function FindUserByUsername(username: string) {
  return await db.user.findUnique({
    where: {
      username,
    },
  });
}

export { CreateUser, FindUserByUsername };
