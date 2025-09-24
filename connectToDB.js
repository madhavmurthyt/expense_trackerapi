import postgres from "postgres";
import dotenv from "dotenv";
dotenv.config();


if (!process.env.DATABASE_URL) {
    throw new Error("DATABASE_URL environment variable not set");
  }
  const sql = postgres(process.env.DATABASE_URL);


export default sql;