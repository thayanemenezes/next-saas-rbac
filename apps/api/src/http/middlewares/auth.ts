import { FastifyInstance } from 'fastify'

import { UnauthorizedError } from '../routes/auth/_errors/unauthorized-error'

export async function auth(app: FastifyInstance) {
  app.addHook('preHandler', async (request) => {
    request.getCurrentUserId = async () => {
      try {
        const { sub } = await request.jwtVerify<{ sub: string }>()
        return sub
      } catch (error) {
        throw new UnauthorizedError('Invalid auth token.')
      }
    }
  })
}
