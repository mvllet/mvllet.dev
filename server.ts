import express, { Request, Response } from "express";
import compression from "compression";
import path from "path";
import rateLimit from "express-rate-limit";

const app = express();
const PORT: number = Number(process.env.PORT) || 3000;

app.disable("x-powered-by");
app.set("trust proxy", 1);

app.use(compression());

const limiter = rateLimit({
    windowMs: 60 * 1000,
    max: 30,
});

app.use(limiter);

app.use(express.static(path.join(process.cwd(), "public")));

app.get("/health", (_req: Request, res: Response) => {
    res.send("OK");
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
