import 'reflect-metadata';
import compression from 'compression';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import express from 'express';
import hpp from 'hpp';
import swaggerJSDoc from 'swagger-jsdoc';
import swaggerUi from 'swagger-ui-express';
import { NODE_ENV, PORT, LOG_FORMAT, ORIGIN, CREDENTIALS } from '@config';
import { DB } from '@database';
import { Routes } from '@interfaces/routes.interface';
import { ErrorMiddleware } from '@middlewares/error.middleware';
import path from 'path';

export class App {
  public app: express.Application;
  public env: string;
  public port: string | number;

  constructor(routes: Routes[]) {
    this.app = express();
    this.env = NODE_ENV || 'development';
    this.port = PORT || 3000;

    this.connectToDatabase();
    this.initializeMiddlewares();
    this.initializeRoutes(routes);
    this.initializeSwagger();
    this.initializeErrorHandling();
  }

  public listen() {
    this.app.listen(this.port, () => {

      console.log(`🚀 App listening on the port ${this.port}`);

    });
  }

  public getServer() {
    return this.app;
  }

  private async connectToDatabase() {
    await DB.sequelize.sync({ force: false });
  }

  private initializeMiddlewares() {
    this.app.use(cors({ origin: ORIGIN, credentials: CREDENTIALS }));
    this.app.use(hpp());
    this.app.use(compression());
    this.app.use(express.json());
    this.app.use(express.urlencoded({ extended: true }));
    this.app.use(cookieParser());
  }

  private initializeRoutes(routes: Routes[]) {
    routes.forEach(route => {
      this.app.use('/', route.router);
    });
  }

  private initializeSwagger() {
    const options = {
      definition: {
        openapi: '3.0.0',
        info: {
          title: 'User API',
          version: '1.0.0',
          description: 'User management API with Swagger',
        },
        servers: [
          {
            url: `http://localhost:${this.port}`,
          },
        ],
      },
      apis: [path.resolve(__dirname, '../routes/*.ts')], // For TypeScript
    };

    const specs = swaggerJSDoc(options);
    this.app.use('/api', swaggerUi.serve, swaggerUi.setup(specs));
  }


  private initializeErrorHandling() {
    this.app.use(ErrorMiddleware);
  }
}
