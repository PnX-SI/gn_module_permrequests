import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Routes, RouterModule } from '@angular/router';
import { HttpClientXsrfModule } from '@angular/common/http';
import { GN2CommonModule } from '@geonature_common/GN2Common.module';
import { NgbModule } from '@ng-bootstrap/ng-bootstrap';

import { AccessRequestService } from './services/accessRequest.service';
import { ListPageComponent } from './pages/list/list.component';
import { AccessRequestInfoPageComponent } from './pages/access-request-info/access-request-info.component';
import { AccessRequestNewPageComponent } from './pages/access-request-new/access-request-new.component';
import { AccessRequestEditPageComponent } from './pages/access-request-edit/access-request-edit.component';
import { AccessRequestResolver } from './resolvers/access-request.resolver';

const routes: Routes = [
  {
    path: '',
    component: ListPageComponent,
  },
  {
    path: 'new',
    component: AccessRequestNewPageComponent,
  },
  {
    path: ':id_access_request',
    component: AccessRequestInfoPageComponent,
    resolve: {
      accessRequestSummary: AccessRequestResolver,
    },
  },
  {
    path: ':id_access_request/edit',
    component: AccessRequestEditPageComponent,
    resolve: {
      accessRequestSummary: AccessRequestResolver,
    },
  },
];

@NgModule({
  imports: [
    HttpClientXsrfModule.withOptions({
      cookieName: 'token',
      headerName: 'token',
    }),
    CommonModule,
    GN2CommonModule,
    NgbModule,
    RouterModule.forChild(routes),
    // Module pages
    AccessRequestEditPageComponent,
    AccessRequestInfoPageComponent,
    AccessRequestNewPageComponent,
    ListPageComponent,
  ],
  providers: [AccessRequestService, AccessRequestResolver],
  bootstrap: [],
})
export class GeonatureModule {}
