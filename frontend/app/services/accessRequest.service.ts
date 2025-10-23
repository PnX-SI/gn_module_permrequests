import { Injectable } from '@angular/core';
import { ConfigService } from '@geonature/services/config.service';

@Injectable()
export class AccessRequestService {
  constructor(public config: ConfigService) {}
}
