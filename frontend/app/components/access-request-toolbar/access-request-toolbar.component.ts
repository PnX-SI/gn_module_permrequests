import { Component, EventEmitter, Input, Output } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { MatDialog } from '@angular/material/dialog';

import { GN2CommonModule } from '@geonature_common/GN2Common.module';
import { ConfirmationDialog } from '@geonature_common/others/modal-confirmation/confirmation.dialog';

import { AccessRequest } from '../../models/accessRequest';
import { AccessRequestService } from '../../services/accessRequest.service';

@Component({
  standalone: true,
  selector: 'access-request-toolbar',
  templateUrl: 'access-request-toolbar.component.html',
  styleUrls: ['./access-request-toolbar.component.scss'],
  imports: [GN2CommonModule, CommonModule, RouterModule],
})
export class AccessRequestToolbarComponent {
  constructor(private _accessRequestService: AccessRequestService,
    private _dialog: MatDialog){}

  @Input()
  accessRequest!: AccessRequest;
  @Output()
  deleted = new EventEmitter<number>();

  get infoRouterLink(): string {
    return `${this.accessRequest.id_access_request}`;
  }

  get editRouterLink(): string {
    return `${this.accessRequest.id_access_request}/edit`;
  }

  deleteAccessRequest(){
    const message =
    "Vous vous apprétez à supprimer la requête d'accès #"+this.accessRequest.id_access_request+"\
     Voulez-vous continuer ? \
    ";
    const dialogRef = this._dialog.open(ConfirmationDialog, {
      width: 'auto',
      // position: { top: '5%' },
      data: { message: message, yesColor: 'basic', noColor: 'warn' },
    });
    dialogRef.afterClosed().subscribe((result: any) => {
      if (result) {
        this._accessRequestService.deleteAccessRequest(this.accessRequest).subscribe(() => {
          this.deleted.emit(this.accessRequest.id_access_request);
        });
      }
    });
  }
}
