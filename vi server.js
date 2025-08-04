import 'dotenv/config';
import express            from 'express';
import cors               from 'cors';
import morgan             from 'morgan';
import helmet             from 'helmet';
import rateLimit          from 'express-rate-limit';
import mongoose           from 'mongoose';
import bcrypt             from 'bcryptjs';
import jwt                from 'jsonwebtoken';
import { v4 as uuid }     from 'uuid';
import AWS                from 'aws-sdk';
import { z }              from 'zod';

// ╭───────────────────────────────────────────────────────────╮
// │  1.  EXPRESS APP & CORE MIDDLEWARE                      │
// ╰───────────────────────────────────────────────────────────╯
const app = express();
app.use(cors());
app.use(helmet());
app.use(express.json({ limit: '10mb' }));
app.use(morgan('dev'));

const limiter = rateLimit({ windowMs: 60_000, max: 120 });
app.use(limiter);

// ╭───────────────────────────────────────────────────────────╮
// │  2.  MONGODB                                             │
// ╰───────────────────────────────────────────────────────────╯
await mongoose.connect(process.env.MONGO_URI);
console.log('✓ Mongo connected');

// Super-lean schemas (everything else is `Mixed`)
const User   = mongoose.model('User',   new mongoose.Schema({ email:{type:String,unique:true}, pwd:String }));
const Vendor = mongoose.model('Vendor', new mongoose.Schema({ name:String, description:String, industry:String, logo:String }));
const Device = mongoose.model('Device', new mongoose.Schema({
  vendor: { type:mongoose.Schema.Types.ObjectId, ref:'Vendor' },
  parameters:Object,
  itemType:String,
  item:Object,
  communicationPolicy:Object,
  messagingPolicy:Object,
  status:{ type:String, default:'pending' },
  createdBy:String,
  createdAt:{ type:Date, default:Date.now },
  provisionedAt:Date,
  awsThing:String
}));

const ItemType   = mongoose.model('ItemType',   new mongoose.Schema({ name:String, description:String, image:String, synonyms:[String], vendors:[{type:mongoose.Schema.Types.ObjectId,ref:'Vendor'}]}));
const Item       = mongoose.model('Item',       new mongoose.Schema({ name:String, code:String, description:String, metadata:String, pollingConfig:String }));
const CommPolicy = mongoose.model('CommPolicy', new mongoose.Schema({ name:String, icon:String, groupName:String, firmwareControlled:Boolean, itemType:String }));
const MsgPolicy  = mongoose.model('MsgPolicy',  new mongoose.Schema({ itemType:String, communicationPolicy:{type:mongoose.Schema.Types.ObjectId, ref:'CommPolicy'} }));
const Parameter  = mongoose.model('Parameter',  new mongoose.Schema({ name:String, type:String, topic:String, unit:String, description:String }));

// ╭───────────────────────────────────────────────────────────╮
// │  3.  HELPERS                                             │
// ╰───────────────────────────────────────────────────────────╯
const wrap = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const ok   = (res, data) => res.json({ ok:true, ...data });
const fail = (res, code, message) => res.status(code).json({ ok:false, error:message });

const JWT_SECRET = process.env.JWT_SECRET || 'very-secret';
const auth = (req,res,next)=>{
  const token = req.headers.authorization?.split(' ')[1];
  if(!token) return fail(res,401,'Token missing');
  try{ req.me = jwt.verify(token,JWT_SECRET); next(); }
  catch{ fail(res,401,'Bad / expired token'); }
};

// ╭───────────────────────────────────────────────────────────╮
// │  4.  AWS-IOT SERVICE                                     │
// ╰───────────────────────────────────────────────────────────╯
AWS.config.update({ region:process.env.AWS_REGION });
const iot = new AWS.Iot();

const iotService = {
  async createThing(serial){
    const thingName = `thing_${serial}_${uuid()}`;
    await iot.createThing({ thingName }).promise();
    return thingName;
  }
};

// ╭───────────────────────────────────────────────────────────╮
// │  5.  VALIDATION (zod)                                    │
// ╰───────────────────────────────────────────────────────────╯
const emailSchema  = z.string().email();
const pwdSchema    = z.string().min(6);
const deviceSchema = z.object({
  vendor     : z.string().optional(),
  parameters : z.object({ serialNumber:z.string() }).passthrough(),
  itemType   : z.string(),
  item       : z.any(),
  communicationPolicy : z.any(),
  messagingPolicy     : z.any()
});

// ╭───────────────────────────────────────────────────────────╮
// │  6.  ROUTES – API v1                                     │
// ╰───────────────────────────────────────────────────────────╯
const api = express.Router();
app.use('/api/v1', api);

// AUTH ───────────────────────────────────────────────────────
api.post('/auth/register', wrap(async (req,res)=>{
  const email = emailSchema.parse(req.body.email).toLowerCase();
  const pwd   = pwdSchema.parse(req.body.password);
  const hash  = await bcrypt.hash(pwd,10);
  await User.create({ email, pwd:hash });
  ok(res,{ message:'Registered' });
}));

api.post('/auth/login', wrap(async (req,res)=>{
  const email = emailSchema.parse(req.body.email).toLowerCase();
  const user  = await User.findOne({ email });
  if(!user || !await bcrypt.compare(req.body.password,user.pwd))
      return fail(res,401,'Bad credentials');

  const token = jwt.sign({ uid:user._id, email:user.email }, JWT_SECRET,{ expiresIn:'8h' });
  ok(res,{ token });
}));

// DEVICES ────────────────────────────────────────────────────
api.get('/devices', auth, wrap(async (_req,res)=> ok(res,{ devices:await Device.find().sort('-createdAt') })));

api.post('/devices', auth, wrap(async (req,res)=>{
  const dto = deviceSchema.parse(req.body);
  const thing = await iotService.createThing(dto.parameters.serialNumber);
  const device = await Device.create({
    ...dto,
    status:'provisioned',
    provisionedAt:new Date(),
    awsThing:thing,
    createdBy:req.me.email
  });
  ok(res,{ device });
}));

// VENDORS ────────────────────────────────────────────────────
api.get('/vendors', auth, wrap(async (_req,res)=> ok(res,{ vendors:await Vendor.find() })));
api.post('/vendors',auth, wrap(async (req,res)=> ok(res,{ vendor:await Vendor.create(req.body) })));

// ITEM TYPES
api.get('/item-types', auth, wrap(async (_req,res)=> ok(res,{ itemTypes:await ItemType.find() })));
api.post('/item-types',auth, wrap(async (req,res)=> ok(res,{ itemType:await ItemType.create(req.body) })));

// ITEMS
api.get('/items', auth, wrap(async (_req,res)=> ok(res,{ items:await Item.find() })));
api.post('/items',auth, wrap(async (req,res)=> ok(res,{ item:await Item.create(req.body) })));

// COMMUNICATION POLICIES
api.get('/communication-policies', auth, wrap(async (_req,res)=> ok(res,{ policies:await CommPolicy.find() })));
api.post('/communication-policies',auth, wrap(async (req,res)=> ok(res,{ policy:await CommPolicy.create(req.body) })));

// MESSAGING POLICIES
api.get('/messaging-policies', auth, wrap(async (_req,res)=> ok(res,{ policies:await MsgPolicy.find().populate('communicationPolicy') })));
api.post('/messaging-policies',auth, wrap(async (req,res)=> ok(res,{ policy:await MsgPolicy.create(req.body) })));

// PARAMETERS
api.get('/parameters', auth, wrap(async (_req,res)=> ok(res,{ parameters:await Parameter.find() })));
api.post('/parameters',auth, wrap(async (req,res)=> ok(res,{ parameter:await Parameter.create(req.body) })));

// ╭───────────────────────────────────────────────────────────╮
// │  7.  STATIC FRONT-END                                    │
// ╰───────────────────────────────────────────────────────────╯
app.use(express.static('public')); // serves index.html & assets

// ╭───────────────────────────────────────────────────────────╮
// │  8.  GLOBAL ERROR HANDLER                                │
// ╰───────────────────────────────────────────────────────────╯
app.use((err, _req, res, _next)=>{
  console.error(err);
  fail(res, 400, err.message || 'Unhandled error');
});

// ╭───────────────────────────────────────────────────────────╮
// │  9.  START                                               │
// ╰───────────────────────────────────────────────────────────╯
const PORT = process.env.PORT ?? 4000;
app.listen(PORT, ()=>console.log(`✓ API ready  →  http://localhost:${PORT}`));
