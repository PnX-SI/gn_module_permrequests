import { inject } from '@angular/core';
import { CanActivateFn, Router, UrlTree } from '@angular/router';
import { catchError, map } from 'rxjs/operators';
import { of } from 'rxjs';

import { ModuleService } from '@geonature/services/module.service';

import { AccessRequestResolver } from '../resolvers/access-request.resolver';
import { ROUTE_PATHS } from '../gnModule.module';
import { AccessRequest } from '../models/accessRequest';

export const canViewAccessRequestGuard: CanActivateFn = (route) => {
  const router = inject(Router);
  const moduleService = inject(ModuleService);
  const accessRequestResolver = inject(AccessRequestResolver);

  // Fallback to the module home page.
  const redirectToAccessRequests = (): UrlTree => {
    return router.createUrlTree([
      `/${moduleService.currentModule?.module_url}/${ROUTE_PATHS.accessRequests}`,
    ]);
  };

  return accessRequestResolver.resolve(route).pipe(
    map((accessRequest: AccessRequest) => {
      if (accessRequest?.cruved?.R) {
        return true;
      }
      return redirectToAccessRequests();
    }),
    catchError(() => of(redirectToAccessRequests()))
  );
};
