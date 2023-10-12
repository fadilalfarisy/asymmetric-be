import express from 'express';
import crypto from 'crypto'
import cors from 'cors'
import bodyParser from 'body-parser';
import dotenv from 'dotenv'

dotenv.config()

const app = express();
app.use(cors());
app.use(bodyParser.json());

//Generate keys
function generateKeyFiles() {
  const keyPair = crypto.generateKeyPairSync('rsa', {
    modulusLength: 530,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
      cipher: 'aes-256-cbc',
      passphrase: ''
    }
  });

  const { publicKey, privateKey } = keyPair
  if (!publicKey || !privateKey) {
    return {
      "publicKey": 'Error',
      "privateKey": 'Error'
    };
  }
  return {
    "publicKey": publicKey,
    "privateKey": privateKey
  };
}

// Creating a function to encrypt string
function encryptString(plaintext, publikKeyFile) {
  try {
    const publicKey = publikKeyFile
    const encrypted = crypto.publicEncrypt(publicKey, Buffer.from(plaintext));
    return encrypted.toString("base64");
  } catch (error) {
    return 'Invalid Public Key'.toString("base64")
  }
}

// Creating a function to decrypt string
function decryptString(ciphertext, privateKeyFile) {
  try {
    const privateKey = privateKeyFile.toString("utf8");
    const decrypted = crypto.privateDecrypt(
      {
        key: privateKey,
        passphrase: '',
      },
      Buffer.from(ciphertext, "base64")
    );
    return decrypted.toString("utf8");
  } catch (error) {
    return 'Invalid Private Key'.toString("utf8")
  }
}

//Formated public key
function formatPublicKey(privateKey) {
  return privateKey.replace("-----BEGIN PUBLIC KEY-----", "-----BEGIN PUBLIC KEY-----\n").replace('-----END PUBLIC KEY-----', '\n-----END PUBLIC KEY-----')
}

//Formated private key
function formatPrivateKey(privateKey) {
  return privateKey.replace("-----BEGIN ENCRYPTED PRIVATE KEY-----", "-----BEGIN ENCRYPTED PRIVATE KEY-----\n").replace('-----END ENCRYPTED PRIVATE KEY-----', '\n-----END ENCRYPTED PRIVATE KEY-----')
}

app.get('/', (req, res) => {
  return res.json({ message: 'OK' });
})

app.get('/generate', (req, res) => {
  const { publicKey, privateKey } = generateKeyFiles();
  return res.json({
    publicKey,
    privateKey,
  });
})

app.post('/encrypt', (req, res) => {
  const {
    plainText,
    publicKey
  } = req.body

  const formatedPublicKey = formatPublicKey(publicKey)
  const encryptedMessage = encryptString(plainText, formatedPublicKey)
  return res.json({
    encryptedMessage
  })
})

app.post('/decode', (req, res) => {
  const {
    encryptedMessage,
    privateKey
  } = req.body

  const formatedPrivateKey = formatPrivateKey(privateKey)
  const decodedMessage = decryptString(encryptedMessage, formatedPrivateKey)
  return res.json({
    decodedMessage: decodedMessage
  })
})

app.listen(process.env.PORT, () => {
  console.log(`server is running on port ${process.env.PORT}`);
})