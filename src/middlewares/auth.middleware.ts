import { NextFunction, Response } from 'express';
import { verify } from 'jsonwebtoken';
import { SECRET_KEY } from '@config';
import { DB } from '@database';
import { DataStoredInToken, RequestWithUser } from '@interfaces/auth.interface';
import { HttpException } from '@/exceptions/HttpException';

const getAuthorization = (req) => {
  // const coockie = req.cookies['Authorization'];
  // if (coockie) return coockie;

  const header = req.header('Authorization');
  if (header) return header.split('Bearer ')[1];

  return null;
}

export const AuthMiddleware =  (scope: Array<string | undefined>)=>{
return async (req: RequestWithUser, res: Response, next: NextFunction) => {
  console.log("ibhr")
  try {
    const Authorization = getAuthorization(req);
    console.log("Authorization",Authorization)

    if (Authorization) {
      const {id} = verify(Authorization, SECRET_KEY) as DataStoredInToken;
      // console.log("verification" , findUser)
      const findUser = await DB.Users.findByPk(id);

      if (findUser) {
        const user = JSON.parse(JSON.stringify(findUser));
        console.log("scopechekc",user.scope ,!scope || scope.includes(user.scope))
        req.user = user;
        
        if(!scope || scope.includes(user.scope)){
          next();
        }else{
          res.status(400).send({ message: 'User does not have sufficient permission', status: 400, response: null });
        }
      } else {
        next(new HttpException(401, 'Wrong authentication token'));
      }
    } else {
      next(new HttpException(404, 'Authentication token missing'));
    }
  } catch (error) {
    next(new HttpException(401, 'Wrong authentication token'));
  }
};
};
