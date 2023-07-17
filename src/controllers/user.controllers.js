const catchError = require("../utils/catchError");
const User = require("../models/User");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const sendEmail = require("../utils/sendEmail");
const EmailCode = require("../models/EmailCode");

const getAll = catchError(async (req, res) => {
  const results = await User.findAll();
  return res.json(results);
});

const create = catchError(async (req, res) => {
  const { email, password, firstName, lastName, country, image, frontBaseUrl } =
    req.body;
  const encriptedPassword = await bcrypt.hash(password, 10);
  const result = await User.create({
    email,
    password: encriptedPassword,
    firstName,
    lastName,
    country,
    image,
  });
  const code = require("crypto").randomBytes(32).toString("hex");
  const link = `${frontBaseUrl}/auth/verify_email/${code}`;

  await EmailCode.create({ code, userId: result.id });

  await sendEmail({
    to: `${email}`,
    subject: "Verfy email for user app",
    html: `<h1 style="color:blue">Hello ${firstName} ${lastName} </h1>
            <p> verify your account click this link</p>
              <a href="${link}">${link}</a>
            <hr>
            <b> thanks for sign up in Users app</b>
            `,
  });
  return res.status(201).json(result);
});

const getOne = catchError(async (req, res) => {
  const { id } = req.params;
  const result = await User.findByPk(id);
  if (!result) return res.sendStatus(404);
  return res.json(result);
});

const remove = catchError(async (req, res) => {
  const { id } = req.params;
  await User.destroy({ where: { id } });
  return res.sendStatus(204);
});

const update = catchError(async (req, res) => {
  const { firstName, lastName, country, image } = req.body;
  const { id } = req.params;
  const result = await User.update(
    { firstName, lastName, country, image },
    {
      where: { id },
      returning: true,
    }
  );
  if (result[0] === 0) return res.sendStatus(404);
  return res.json(result[1][0]);
});

const verifyCode = catchError(async (req, res) => {
  const { code } = req.params;
  const emialCode = await EmailCode.findOne({ where: { code } });
  if (!emialCode) return res.status(401).json({ message: "invalid code" });
  const user = await User.findByPk(emialCode.userId);
  user.isVerified = true;
  await user.save();
  await emialCode.destroy();
  return res.json(user);
});

const login = catchError(async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ where: { email } });
  if (!user) return res.status(401).json({ error: "invalid credentials" });

  const isValid = await bcrypt.compare(password, user.password);
  if (!isValid) return res.status(401).json({ error: "invalid credentials" });

  if (!user.isVerified)
    return res.status(401).json({ error: "invalid credentials" });

  const token = jwt.sign(
    { user },
    process.env.TOKEN_SECRET
    // { expiresIn: '5m' }
  );

  return res.json({ user, token });
});

const getLoggedUser = catchError(async (req, res) => {
  const user = req.user;
  return res.json(user);
});

const resetPassword = catchError(async (req, res) => {
  const { email, frontBaseUrl } = req.body;

  const user = await User.findOne({ where: { email } });
  if (!user) return res.status(401).json({ error: "invalid credentials" });

  const code = require("crypto").randomBytes(32).toString("hex");
  const link = `${frontBaseUrl}/reset_password/${code}`;

  const hasACode = await EmailCode.findOne({ where: { userId: user.id } });

  if (!hasACode) await EmailCode.create({ code, userId: user.id });

  await EmailCode.update({ code }, { where: { userId: user.id } });

  await sendEmail({
    to: `${email}`,
    subject: "reset Password",
    html: `<h1 style="color:blue">Hello ${user.firstName} ${user.lastName} </h1>
            <p> to reset your account password, click on this link</p>
              <a href="${link}">${link}</a>
            `,
  });
  return res.sendStatus(202);
});

const verifyResetPassword = catchError(async (req, res) => {
  const { code } = req.params;
  const { password } = req.body;

  const result = await EmailCode.findOne({ where: { code } });
  if (!result) return res.sendStatus(401);

  const encriptedPassword = await bcrypt.hash(password, 10);
  const user = await User.findByPk(result.userId);
  user.password = encriptedPassword;
  await user.save();
  await result.destroy();

  return res.sendStatus(200);
});

module.exports = {
  getAll,
  create,
  getOne,
  remove,
  update,
  verifyCode,
  login,
  getLoggedUser,
  resetPassword,
  verifyResetPassword,
};
