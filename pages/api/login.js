import { query as q } from 'faunadb';
import { guestClient } from '../../utils/fauna-client';
import { setAuthCookie } from '../../utils/auth-cookies';
import NextCors from 'nextjs-cors';

export default async function login(req, res) {

  await NextCors(req, res, {
      // Options
      methods: ['GET', 'HEAD', 'PUT', 'PATCH', 'POST', 'DELETE'],
      origin: '*',
      optionsSuccessStatus: 200, // some legacy browsers (IE11, various SmartTVs) choke on 204
   });
  
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).send('Email and Password not provided');
  }

  try {
    const auth = await guestClient.query(
      q.Login(q.Match(q.Index('user_by_email'), q.Casefold(email)), {
        password,
      })
    );

    if (!auth.secret) {
      return res.status(404).send('auth secret is missing');
    }

    setAuthCookie(res, auth.secret);

    res.status(200).json({token: auth.secret});
  } catch (error) {
    console.error(error);
    res.status(error.requestResult.statusCode).send(error.message);
  }
}
