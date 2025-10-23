import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Routes, RouterModule } from '@angular/router';
import { HttpClientXsrfModule } from '@angular/common/http';
import { GN2CommonModule } from '@geonature_common/GN2Common.module';
import { NgbModule } from '@ng-bootstrap/ng-bootstrap';


import { AccessRequestService } from './services/accessRequest.service';
import { ListComponent } from './pages/list/list.component';

const routes: Routes = [{ path: '', component: ListComponent }];

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
    ListComponent
  ],
  providers: [AccessRequestService],
  bootstrap: [],
})
export class GeonatureModule {}
