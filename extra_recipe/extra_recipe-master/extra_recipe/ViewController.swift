//
//  ViewController.swift
//  extra_recipe
//
//  Created by Ian Beer on 1/23/17.
//  Copyright © 2017 Ian Beer. All rights reserved.
//

import UIKit

class ViewController: UIViewController {

  override func viewDidLoad() {
    super.viewDidLoad()
    //DispatchQueue.main.async(execute: { () -> Void in
    //  jb_go();
    //})
  }


  override func didReceiveMemoryWarning() {
    super.didReceiveMemoryWarning()
    // Dispose of any resources that can be recreated.
  }

  @IBAction func bang(_ sender: UIButton) {
    var status: String
    switch jb_go() {
        case 0:
            status = "jailbroken"
        case 1:
            status = "internal error"
        case 2:
            status = "unsupported"
        case 3:
            status = "unsupported yet"
        case 42:
            status = "hmm... ok"
        default:
            status = "failed, reboot"
    }
    sender.isEnabled = false
    sender.setTitle(status, for: .disabled)
  }

}

