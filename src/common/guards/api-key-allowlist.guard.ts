import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
} from '@nestjs/common';
import { isIP, inRange } from 'range_check';

@Injectable()
export class ApiKeyAllowlistGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest();
    const apiKey = request['apiKey']; // Populated by prior Auth Guard
    if (!apiKey || !apiKey.allowlistCidrs || apiKey.allowlistCidrs.length === 0) {
      return true; // Empty allowlist preserves default behavior
    }

    const clientIp = this.extractClientIp(request);
    if (!clientIp) {
      throw new ForbiddenException('Unable to resolve client IP address');
    }

    const isAllowed = apiKey.allowlistCidrs.some((cidr: string) =>
      inRange(clientIp, cidr),
    );

    if (!isAllowed) {
      throw new ForbiddenException(`IP address ${clientIp} is not authorized`);
    }

    return true;
  }

  private extractClientIp(req: any): string {
    const trustedProxyHeader = req.headers['x-forwarded-for'];
    if (trustedProxyHeader) {
      const ips = trustedProxyHeader.split(',').map((ip: string) => ip.trim());
      return ips[0];
    }
    return req.socket?.remoteAddress || req.ip;
  }
}
