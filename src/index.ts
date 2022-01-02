require('dotenv').config()

import express from 'express' 
import bodyParser from 'body-parser'
import nacl from 'tweetnacl'
import winston from 'winston'
import axios from 'axios'

const PORT = parseInt(process.env.PORT, 10)
const PUBLIC_KEY = process.env.PUBLIC_KEY
const FORWARDING_URL = process.env.FORWARDING_URL

const logger = module.exports = winston.createLogger({
    transports: [new winston.transports.Console()],
    level: process.env.NODE_ENV === 'production' ? "info" : "debug",
    format: winston.format.combine(
        winston.format.colorize({ all: true }),
        winston.format.timestamp(),
        winston.format.simple()
    )
});

const app = express()

const isSignatureValid = (signature: string, timestamp: string, body: Buffer) => {
    const b = body.toString()
    return nacl.sign.detached.verify(
        Buffer.from(timestamp + b),
        Buffer.from(signature, 'hex'),
        Buffer.from(PUBLIC_KEY, 'hex')
    )
}

const signatureValidation = (req: express.Request, res: express.Response, next: express.NextFunction) => {
    const signature = req.get('X-Signature-Ed25519')
    const timestamp = req.get('X-Signature-Timestamp')

    if (isSignatureValid(signature, timestamp, req.body)) {
        logger.info("Validated singature")
        next()
    } else {
        logger.info("Signature invalid")
        res.status(401).send()
    }
}

app.use("/app", bodyParser.raw({ inflate: true, limit: '100kb', type: 'application/json' }))
app.use("/app", signatureValidation)

app.post("/app", async (req: express.Request, res: express.Response) => {
    const parsedBody = JSON.parse(req.body)

    logger.debug(JSON.stringify(parsedBody))

    const proxyResponse = await axios.post(`${FORWARDING_URL}`, parsedBody)

    logger.debug(`Downstream HTTP service response: ${proxyResponse.status} ${proxyResponse.data.toString()}`)
    res.status(proxyResponse.status).json(proxyResponse.data)
})

// TODO: Add error handling

app.listen(PORT, () => logger.info(`Listening on ${PORT}`))