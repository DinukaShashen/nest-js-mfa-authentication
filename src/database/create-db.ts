// src/database/create-db.ts
import { createDatabase } from 'typeorm-extension';

async function bootstrap() {
  try {
    await createDatabase({
      ifNotExist: true, // only create if missing
      options: {
        type: 'postgres',
        host: process.env.DATABASE_HOST || 'localhost',
        port: parseInt(process.env.DATABASE_PORT || '5432', 10),
        username: process.env.DATABASE_USER || 'postgres',
        password: process.env.DATABASE_PASSWORD || 'admin',
        database: 'postgres', // connect to default 'postgres' DB first
      },
    });

    console.log('Database checked/created successfully!');
  } catch (err) {
    console.error('Database creation failed:', err);
  }
}

void bootstrap();
