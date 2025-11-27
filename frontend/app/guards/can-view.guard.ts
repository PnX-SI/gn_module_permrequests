import { inject } from '@angular/core';
import { CanActivateFn, Router, UrlTree } from '@angular/router';
import { catchError, map } from 'rxjs/operators';
import { of } from 'rxjs';

import { ModuleService } from '@geonature/services/module.service';

import { PermissionRequestResolver } from '../resolvers/permission-request.resolver';
import { ROUTE_PATHS } from '../gnModule.module';
import { PermissionRequest } from '../models/permissionRequest';

export const canViewGuard: CanActivateFn = (route) => {
  const router = inject(Router);
  const moduleService = inject(ModuleService);
  const permissionRequestResolver = inject(PermissionRequestResolver);

  // Fallback to the module home page.
  const redirectToPermissionRequests = (): UrlTree => {
    return router.createUrlTree([
      `/${moduleService.currentModule?.module_url}/${ROUTE_PATHS.permissionRequests}`,
    ]);
  };

  return permissionRequestResolver.resolve(route).pipe(
    map((permissionRequest: PermissionRequest) => {
      if (permissionRequest?.cruved?.R) {
        return true;
      }
      return redirectToPermissionRequests();
    }),
    catchError(() => of(redirectToPermissionRequests()))
  );
};
